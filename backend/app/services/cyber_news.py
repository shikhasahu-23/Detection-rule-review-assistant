from __future__ import annotations

import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from html import unescape

NEWS_FEEDS = [
    ("CISA", "https://www.cisa.gov/news-events/cybersecurity-advisories.xml"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
]

def _text(element: ET.Element, names: tuple[str, ...]) -> str:
    for child in element.iter():
        if child.tag.split("}")[-1].lower() in names and child.text:
            return child.text.strip()
    return ""

def _clean(value: str) -> str:
    value = re.sub(r"<[^>]+>", " ", value or "")
    return re.sub(r"\s+", " ", unescape(value)).strip()

def _severity(text: str) -> str:
    value = text.lower()
    if any(term in value for term in ("zero-day", "zero day", "actively exploited", "ransomware", "mass exploitation", "critical vulnerability", "remote code execution")):
        return "critical"
    if any(term in value for term in ("breach", "data leak", "data theft", "exploited", "vulnerability", "malware", "phishing", "supply chain", "nation-state")):
        return "high"
    if any(term in value for term in ("patch", "security update", "disclosure", "cyberattack", "attack", "campaign")):
        return "medium"
    return "low"

def _impact(text: str, severity: str) -> str:
    value = text.lower()
    if any(term in value for term in ("ransomware", "encrypt", "extort")):
        return "Potential service disruption, data loss and extortion."
    if any(term in value for term in ("data breach", "data leak", "exposed records", "stolen data")):
        return "Potential exposure of sensitive data and regulatory impact."
    if any(term in value for term in ("zero-day", "actively exploited", "remote code execution")):
        return "Systems may be compromised before or without a patch."
    if any(term in value for term in ("phishing", "credential", "account takeover")):
        return "Risk of credential theft and unauthorized account access."
    if any(term in value for term in ("supply chain", "third-party")):
        return "A supplier compromise may affect downstream organizations."
    if severity == "high":
        return "Elevated risk; check affected products, exposure and available mitigations."
    if severity == "medium":
        return "Review relevance to your environment and track recommended fixes."
    return "Situational awareness; assess relevance to your environment."

def get_cyber_news(limit: int = 60) -> dict:
    stories: list[dict] = []
    feed_errors: list[str] = []
    for source, url in NEWS_FEEDS:
        request = urllib.request.Request(url, headers={"User-Agent": "ThreatWeave/1.0 security-news-reader"})
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                root = ET.fromstring(response.read(2_000_000))
            entries = [node for node in root.iter() if node.tag.split("}")[-1].lower() in ("item", "entry")]
            for entry in entries[:30]:
                title = _clean(_text(entry, ("title",)))
                link = _text(entry, ("link",))
                if not link:
                    link_node = next((node for node in entry.iter() if node.tag.split("}")[-1].lower() == "link"), None)
                    link = link_node.attrib.get("href", "") if link_node is not None else ""
                description = _clean(_text(entry, ("description", "summary", "content", "encoded")))
                published_raw = _text(entry, ("pubdate", "published", "updated", "date"))
                try:
                    published = parsedate_to_datetime(published_raw) if published_raw else datetime.now(UTC)
                    if published.tzinfo is None:
                        published = published.replace(tzinfo=UTC)
                except (TypeError, ValueError, OverflowError):
                    try:
                        published = datetime.fromisoformat(published_raw)
                    except (TypeError, ValueError):
                        published = datetime.now(timezone.utc)
                if not title or not link:
                    continue
                combined = f"{title}. {description}"
                severity = _severity(combined)
                stories.append({
                    "id": f"{source}:{link}", "headline": title,
                    "summary": description[:420] if description else "Open the source article for the full report.",
                    "impact": _impact(combined, severity), "severity": severity,
                    "source": source, "url": link, "published_at": published.isoformat(),
                })
        except (urllib.error.URLError, TimeoutError, OSError, ET.ParseError, ValueError) as exc:
            feed_errors.append(f"{source}: {type(exc).__name__}")
    unique = {story["url"]: story for story in stories}
    ordered = sorted(unique.values(), key=lambda story: story["published_at"], reverse=True)
    return {"items": ordered[:limit], "sources_checked": len(NEWS_FEEDS), "sources_failed": feed_errors,
            "fetched_at": datetime.now(timezone.utc).isoformat()}
