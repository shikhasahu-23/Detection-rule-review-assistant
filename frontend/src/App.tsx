import { useCallback, useEffect, useState } from "react";
import {
  Activity, AlertTriangle, ArrowUpRight, BrainCircuit, CheckCircle2, ChevronRight,
  Database, FileSearch, Layers3, LoaderCircle, Radar, RefreshCw, ShieldCheck,
  ShieldEllipsis, Sparkles, Search
} from "lucide-react";

const API = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";
type Summary = { indicators_total: number; active_indicators: number; sources_total: number; latest_run: { source: string; status: string; started_at: string; records_seen: number; indicators_created: number } | null };
type Indicator = { id: string; indicator_type: string; value: string; confidence: number; severity: string; status: string; description: string | null; tags: string[]; created_at: string };
type Feed = { name: string; status: string; last_run: string; records_seen: number; indicators_created: number };

const nav = [
  { label: "Overview", icon: Layers3 },
  { label: "Threat intelligence", icon: Radar },
  { label: "Rule generator", icon: Sparkles },
  { label: "Validation", icon: ShieldCheck },
  { label: "Review queue", icon: FileSearch },
  { label: "Rule library", icon: Database },
];

function App() {
  const [page, setPage] = useState("Overview");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const loadData = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [s, i, f] = await Promise.all([
        fetch(`${API}/api/v1/intelligence/summary`),
        fetch(`${API}/api/v1/intelligence/indicators?limit=100`),
        fetch(`${API}/api/v1/intelligence/feeds`),
      ]);
      if (![s, i, f].every((r) => r.ok)) throw new Error("The API is unavailable. Start the backend and database, then retry.");
      setSummary(await s.json());
      setIndicators(await i.json());
      setFeeds(await f.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load intelligence data.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void loadData(); }, [loadData]);

  const syncCisa = async () => {
    setSyncing(true); setError(""); setNotice("");
    try {
      const response = await fetch(`${API}/api/v1/intelligence/feeds/cisa-kev/sync`, { method: "POST" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "CISA feed sync failed.");
      setNotice(`CISA KEV sync complete — ${body.records_seen.toLocaleString()} records checked, ${body.indicators_created.toLocaleString()} new indicators added.`);
      await loadData();
    } catch (e) {
      setError(e instanceof Error ? e.message : "CISA feed sync failed.");
    } finally {
      setSyncing(false);
    }
  };

  const filtered = indicators.filter((item) =>
    item.value.toLowerCase().includes(query.toLowerCase()) ||
    (item.description || "").toLowerCase().includes(query.toLowerCase())
  );
  const stats = [
    { label: "Active intelligence", value: summary?.active_indicators ?? "—", note: "Active indicators stored", icon: Radar },
    { label: "Total indicators", value: summary?.indicators_total ?? "—", note: "Deduplicated records", icon: BrainCircuit },
    { label: "Connected sources", value: summary?.sources_total ?? "—", note: "Sources with evidence", icon: Database },
    { label: "Feed runs", value: feeds.length, note: "Sources with run history", icon: RefreshCw },
  ];

  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><div className="brandmark"><ShieldEllipsis /></div><div><b>ThreatWeave</b><small>THREAT INTELLIGENCE &amp; DETECTION</small></div></div>
      <label>WORKSPACE</label>
      <div className="workspace"><span>S</span><div><b>Security Engineering</b><small>Team workspace</small></div><ChevronRight size={15}/></div>
      <nav>{nav.map(({ label, icon: Icon }) => <button key={label} className={page === label ? "nav active" : "nav"} onClick={() => setPage(label)}><Icon size={17}/>{label}</button>)}</nav>
      <div className="sidebottom"><span className="live-dot"/> Platform initialized<hr/><div className="user"><b>SE</b><div>Team member<small>Workspace access</small></div></div></div>
    </aside>
    <main>
      <header><span>Workspace　›　<b>{page}</b></span><small><span className="live-dot"/> DEVELOPMENT</small></header>
      <section className="heading">
        <div><label>DETECTION ENGINEERING WORKSPACE</label><h1>{page === "Threat intelligence" ? "Threat Intelligence Center" : "Good morning, team 👋"}</h1><p>Monitor threat intelligence, preserve source evidence, and prepare trusted inputs for detection engineering.</p></div>
        {page === "Threat intelligence" && <button onClick={syncCisa} disabled={syncing}><RefreshCw size={16} className={syncing ? "spin" : ""}/>{syncing ? "Syncing CISA KEV…" : "Sync CISA KEV"}</button>}
      </section>
      {error && <div className="notice error"><AlertTriangle size={16}/>{error}<button onClick={loadData}>Retry</button></div>}
      {notice && <div className="notice success"><CheckCircle2 size={16}/>{notice}</div>}
      {page === "Threat intelligence" ? <>
        <section className="banner"><Radar/><div><b>CISA Known Exploited Vulnerabilities</b><p>Official CISA KEV catalogue · fixed trusted HTTPS source · idempotent ingestion with source provenance.</p></div><span>{feeds.find(f => f.name === "CISA KEV")?.status?.toUpperCase() || "NOT SYNCED"}</span></section>
        <section className="stats">{stats.map(({ label, value, note, icon: Icon }) => <article key={label}><div>{label}<Icon size={18}/></div><strong>{loading ? "…" : value.toLocaleString?.() ?? value}</strong><small>{note}</small></article>)}</section>
        <section className="panel intel-panel">
          <div className="panelhead"><div><b>Indicator inventory</b><p>Normalized indicators with source-backed evidence</p></div><span>{filtered.length} records</span></div>
          <div className="searchbar"><Search size={16}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search CVE or description…"/><button onClick={loadData} title="Refresh"><RefreshCw size={15}/></button></div>
          <div className="table-wrap"><table><thead><tr><th>INDICATOR</th><th>TYPE</th><th>SEVERITY</th><th>CONFIDENCE</th><th>STATUS</th></tr></thead><tbody>
            {filtered.map(item => <tr key={item.id}><td><b>{item.value}</b><small>{item.description || item.tags.join(" · ") || "No description supplied"}</small></td><td><span className="type-pill">{item.indicator_type.toUpperCase()}</span></td><td><span className={`severity ${item.severity}`}>{item.severity}</span></td><td>{item.confidence}%</td><td><span className="status-pill">{item.status}</span></td></tr>)}
            {!loading && filtered.length === 0 && <tr><td colSpan={5} className="no-data">{query ? "No indicators match this search." : "No indicators yet. Sync the CISA KEV feed to populate the inventory."}</td></tr>}
          </tbody></table></div>
        </section>
        <section className="panel feed-panel"><div className="panelhead"><div><b>Feed activity</b><p>Recent ingestion status</p></div></div>
          {feeds.length ? feeds.map(feed => <div className="feed-row" key={feed.name}><div><b>{feed.name}</b><small>{feed.last_run ? new Date(feed.last_run).toLocaleString() : "No run time"}</small></div><span className={feed.status === "succeeded" ? "feed-ok" : "feed-fail"}>{feed.status}</span><small>{feed.records_seen.toLocaleString()} records · {feed.indicators_created.toLocaleString()} new</small></div>) : <p className="muted">No feed runs recorded. Start with the CISA KEV sync.</p>}
        </section>
      </> : <>
        <section className="banner"><Activity/><div><b>Your workspace is ready for detection engineering</b><p>Start by ingesting trusted intelligence. Rule generation and approval workflows will build on this foundation.</p></div><span>PHASE 2</span></section>
        <section className="stats">{stats.map(({label,value,note,icon:Icon})=><article key={label}><div>{label}<Icon size={18}/></div><strong>{loading ? "…" : value.toLocaleString?.() ?? value}</strong><small>{note}</small></article>)}</section>
        <section className="columns"><article className="panel"><div className="panelhead"><div><b>Core workflow</b><p>Build the intelligence-to-detection pipeline.</p></div></div>
          {[{title:"Ingest threat intelligence",desc:"CISA KEV connector is available in Threat Intelligence.",icon:Radar},{title:"Enrich and correlate",desc:"Normalize evidence and map relationships and ATT&CK techniques.",icon:Database},{title:"Generate detection candidates",desc:"Create platform-specific detections with an AI provider.",icon:Sparkles},{title:"Validate and review",desc:"Run deterministic checks and require human approval.",icon:ShieldCheck}].map(({title,desc,icon:Icon})=><div className="step" key={title}><Icon/><div><b>{title}</b><small>{desc}</small></div><label>ROADMAP</label><ChevronRight size={15}/></div>)}
        </article><article className="panel activity"><div className="panelhead"><div><b>Latest intelligence run</b><p>Most recent feed execution</p></div><ArrowUpRight/></div><div className="empty"><CheckCircle2/><b>{summary?.latest_run ? summary.latest_run.status : "Waiting for first sync"}</b><p>{summary?.latest_run ? `${summary.latest_run.records_seen} records checked from ${summary.latest_run.source}.` : "Open Threat Intelligence and run the CISA KEV connector to start."}</p><button onClick={() => setPage("Threat intelligence")}>Open Intelligence Center</button></div></article></section>
      </>}
      <div className="footnote"><AlertTriangle size={15}/> Intelligence feed content is treated as untrusted evidence. Generated detections remain candidates until validated and approved; production deployment is disabled.</div>
      <footer>THREATWEAVE　•　THREAT INTELLIGENCE &amp; DETECTION ENGINEERING</footer>
    </main>
  </div>;
}
export default App;
