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
type DetectionIntent = { id: string; title: string; description: string; behavior: string; severity: string; target_platforms: string[]; status: string };
type RuleCandidate = { id: string; name: string; platform: string; query: string; version: number; status: string; validation_status: string; validation_report: { errors: {code:string;message:string}[]; warnings: {code:string;message:string}[]; is_deployable: boolean }; generator: string };
type AttackTechnique = { id: string; external_id: string; name: string; description: string; platforms: string[]; tactics: string[]; is_subtechnique: boolean; revoked: boolean; deprecated: boolean; source_url: string };

const nav = [
  { label: "Overview", icon: Layers3 },
  { label: "Threat intelligence", icon: Radar },
  { label: "ATT&CK catalog", icon: ShieldCheck },
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
  const [syncingNvd, setSyncingNvd] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [intents, setIntents] = useState<DetectionIntent[]>([]);
  const [candidates, setCandidates] = useState<RuleCandidate[]>([]);
  const [selectedIntentId, setSelectedIntentId] = useState("");
  const [intentTitle, setIntentTitle] = useState("");
  const [intentDescription, setIntentDescription] = useState("");
  const [intentBehavior, setIntentBehavior] = useState("");
  const [targetPlatforms, setTargetPlatforms] = useState<string[]>(["splunk", "sentinel"]);
  const [creatingIntent, setCreatingIntent] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [attackTechniques, setAttackTechniques] = useState<AttackTechnique[]>([]);
  const [attackSearch, setAttackSearch] = useState("");
  const [syncingAttack, setSyncingAttack] = useState(false);
  const [uploadingCsv, setUploadingCsv] = useState(false);

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

  const importCsv = async (file: File) => {
    setUploadingCsv(true); setError(""); setNotice("");
    try {
      const response = await fetch(`${API}/api/v1/intelligence/feeds/custom/csv`, {
        method: "POST", headers: { "Content-Type": "text/csv" }, body: file,
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "CSV import failed.");
      setNotice(`CSV import ${body.status}: ${body.indicators_created} new indicators, ${body.evidence_created} evidence records, ${body.rejected_count} rejected rows.`);
      await loadData();
    } catch (e) {
      setError(e instanceof Error ? e.message : "CSV import failed.");
    } finally { setUploadingCsv(false); }
  };

  const loadAttackCatalog = useCallback(async () => {
    try {
      const response = await fetch(`${API}/api/v1/intelligence/attack-techniques?limit=500`);
      if (!response.ok) throw new Error("Unable to load ATT&CK catalog.");
      setAttackTechniques(await response.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load ATT&CK catalog.");
    }
  }, []);

  useEffect(() => {
    if (page === "ATT&CK catalog") void loadAttackCatalog();
  }, [page, loadAttackCatalog]);

  const syncAttack = async () => {
    setSyncingAttack(true); setError(""); setNotice("");
    try {
      const response = await fetch(`${API}/api/v1/intelligence/feeds/mitre-attack/sync`, { method: "POST" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "ATT&CK catalog sync failed.");
      setNotice(`ATT&CK sync complete — ${body.techniques_created} new and ${body.techniques_updated} updated techniques.`);
      await loadAttackCatalog();
    } catch (e) {
      setError(e instanceof Error ? e.message : "ATT&CK catalog sync failed.");
    } finally { setSyncingAttack(false); }
  };

  const loadDetectionData = useCallback(async () => {
    try {
      const response = await fetch(`${API}/api/v1/detection-intents?limit=100`);
      if (!response.ok) throw new Error("Unable to load detection intents.");
      const items: DetectionIntent[] = await response.json();
      setIntents(items);
      const currentId = selectedIntentId || items[0]?.id || "";
      if (!selectedIntentId && currentId) setSelectedIntentId(currentId);
      if (currentId) {
        const rulesResponse = await fetch(`${API}/api/v1/detection-intents/${currentId}/candidates`);
        if (!rulesResponse.ok) throw new Error("Unable to load rule candidates.");
        setCandidates(await rulesResponse.json());
      } else setCandidates([]);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load detection engineering data.");
    }
  }, [selectedIntentId]);

  useEffect(() => {
    if (["Rule generator", "Validation", "Review queue", "Rule library"].includes(page)) void loadDetectionData();
  }, [page, loadDetectionData]);

  const createIntent = async () => {
    setCreatingIntent(true); setError(""); setNotice("");
    try {
      const response = await fetch(`${API}/api/v1/detection-intents`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: intentTitle, description: intentDescription, behavior: intentBehavior,
          severity: "medium", target_platforms: targetPlatforms,
          required_telemetry: [{ source: "endpoint", description: "Process creation and network telemetry", required_fields: ["process_name", "command_line", "destination_ip"] }],
          test_scenarios: [],
        }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Unable to create detection intent.");
      setIntentTitle(""); setIntentDescription(""); setIntentBehavior("");
      setSelectedIntentId(body.id);
      setNotice("Detection intent saved. You can now generate platform-specific candidates.");
      await loadDetectionData();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to create detection intent.");
    } finally { setCreatingIntent(false); }
  };

  const generateRules = async () => {
    if (!selectedIntentId) return;
    setGenerating(true); setError(""); setNotice("");
    try {
      const response = await fetch(`${API}/api/v1/detection-intents/${selectedIntentId}/generate`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_platforms: targetPlatforms }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Candidate generation failed.");
      setNotice(`${body.length} candidate(s) generated. Review the query and validation warnings before using them.`);
      await loadDetectionData();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Candidate generation failed.");
    } finally { setGenerating(false); }
  };

  const selectedIntent = intents.find((item) => item.id === selectedIntentId);
  const syncNvd = async () => {
    setSyncingNvd(true); setError(""); setNotice("");
    try {
      const response = await fetch(`${API}/api/v1/intelligence/feeds/nvd/sync`, { method: "POST" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "NVD sync failed.");
      setNotice(`NVD sync complete — ${body.records_seen.toLocaleString()} records checked, ${body.indicators_created.toLocaleString()} new indicators added.${body.complete_window ? "" : " The result window was larger than one page; another sync is needed to complete it."}`);
      await loadData();
    } catch (e) {
      setError(e instanceof Error ? e.message : "NVD sync failed.");
    } finally { setSyncingNvd(false); }
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
        <div><label>DETECTION ENGINEERING WORKSPACE</label><h1>{page === "Threat intelligence" ? "Threat Intelligence Center" : page === "ATT&CK catalog" ? "MITRE ATT&CK Catalog" : page === "Rule generator" ? "Detection Rule Generator" : "Good morning, team 👋"}</h1><p>Monitor threat intelligence, preserve source evidence, and prepare trusted inputs for detection engineering.</p></div>
        {page === "Threat intelligence" && <div className="feed-actions"><button onClick={syncCisa} disabled={syncing||syncingNvd}><RefreshCw size={16} className={syncing ? "spin" : ""}/>{syncing ? "Syncing CISA…" : "Sync CISA KEV"}</button><button onClick={syncNvd} disabled={syncing||syncingNvd}><RefreshCw size={16} className={syncingNvd ? "spin" : ""}/>{syncingNvd ? "Syncing NVD…" : "Sync NVD CVEs"}</button><label className="upload-button">{uploadingCsv?"Importing CSV…":"Import CSV"}<input type="file" accept=".csv,text/csv" disabled={uploadingCsv} onChange={e=>{const input=e.currentTarget;const file=input.files?.[0];input.value="";if(file)void importCsv(file);}}/></label></div>}
        {page === "ATT&CK catalog" && <button onClick={syncAttack} disabled={syncingAttack}><RefreshCw size={16} className={syncingAttack ? "spin" : ""}/>{syncingAttack ? "Syncing catalog…" : "Sync ATT&CK"}</button>}
      </section>
      {error && <div className="notice error"><AlertTriangle size={16}/>{error}<button onClick={loadData}>Retry</button></div>}
      {notice && <div className="notice success"><CheckCircle2 size={16}/>{notice}</div>}
      {page === "Threat intelligence" ? <>
        <section className="banner"><Radar/><div><b>CISA Known Exploited Vulnerabilities</b><p>CISA KEV and NVD CVE catalogues · fixed trusted HTTPS sources · idempotent ingestion with source provenance.</p></div><span>{feeds.find(f => f.name === "CISA KEV")?.status?.toUpperCase() || "NOT SYNCED"}</span></section>
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
      </> : page === "ATT&CK catalog" ? <>
        <section className="banner"><ShieldCheck/><div><b>MITRE ATT&CK Enterprise</b><p>Technique and sub-technique reference catalog with tactic and platform metadata. Deprecated and revoked entries remain visible for historical references.</p></div><span>{attackTechniques.length} TECHNIQUES</span></section>
        <section className="panel intel-panel"><div className="panelhead"><div><b>Technique catalog</b><p>Search by technique ID, name, platform or tactic.</p></div><span>{attackTechniques.length} loaded</span></div>
          <div className="searchbar"><Search size={16}/><input value={attackSearch} onChange={e=>setAttackSearch(e.target.value)} placeholder="Search T1059, PowerShell, Execution…"/></div>
          <div className="table-wrap"><table><thead><tr><th>TECHNIQUE</th><th>TACTICS</th><th>PLATFORMS</th><th>TYPE</th><th>STATUS</th></tr></thead><tbody>
            {attackTechniques.filter(item=>[item.external_id,item.name,item.description,...item.tactics,...item.platforms].join(" ").toLowerCase().includes(attackSearch.toLowerCase())).map(item=><tr key={item.id}><td><b>{item.external_id} · {item.name}</b><small>{item.description}</small></td><td>{item.tactics.join(", ") || "—"}</td><td>{item.platforms.join(", ") || "—"}</td><td>{item.is_subtechnique?"Sub-technique":"Technique"}</td><td><span className="status-pill">{item.revoked?"Revoked":item.deprecated?"Deprecated":"Active"}</span></td></tr>)}
            {attackTechniques.length===0 && <tr><td colSpan={5} className="no-data">No ATT&CK techniques loaded. Select Sync ATT&CK to import the official catalog.</td></tr>}
          </tbody></table></div>
        </section>
      </> : page === "Rule generator" ? <>
        <section className="banner"><Sparkles/><div><b>AI-assisted detection generation</b><p>Describe behavior once, then create platform-specific draft candidates. Generated queries require analyst review.</p></div><span>HUMAN REVIEW</span></section>
        <section className="columns">
          <article className="panel"><div className="panelhead"><div><b>Create detection intent</b><p>Define behavior and telemetry before generating queries.</p></div></div>
            <div className="intent-form">
              <label>DETECTION NAME</label><input value={intentTitle} onChange={e=>setIntentTitle(e.target.value)} placeholder="e.g. Suspicious PowerShell download"/>
              <label>DESCRIPTION</label><textarea value={intentDescription} onChange={e=>setIntentDescription(e.target.value)} placeholder="What activity should this detection identify?"/>
              <label>BEHAVIOR DETAILS</label><textarea value={intentBehavior} onChange={e=>setIntentBehavior(e.target.value)} placeholder="Describe the attacker behavior, sequence and expected signals."/>
              <label>TARGET PLATFORMS</label><div className="platform-options">{["splunk","sentinel","chronicle","crowdstrike"].map(platform=><label key={platform}><input type="checkbox" checked={targetPlatforms.includes(platform)} onChange={e=>setTargetPlatforms(old=>e.target.checked?[...old,platform]:old.filter(x=>x!==platform))}/>{platform}</label>)}</div>
              <button className="primary-action" disabled={creatingIntent||intentTitle.length<3||intentDescription.length<10||intentBehavior.length<10||targetPlatforms.length===0} onClick={createIntent}>{creatingIntent?"Saving intent…":"Save detection intent"}</button>
            </div>
          </article>
          <article className="panel"><div className="panelhead"><div><b>Generate candidates</b><p>Use the configured OpenAI provider to draft queries.</p></div></div>
            <div className="intent-form">
              <label>SAVED DETECTION INTENT</label><select value={selectedIntentId} onChange={e=>{const id=e.target.value;setSelectedIntentId(id);const found=intents.find(x=>x.id===id);if(found)setTargetPlatforms(found.target_platforms);}}><option value="">Select a detection intent</option>{intents.map(item=><option key={item.id} value={item.id}>{item.title}</option>)}</select>
              <label>PLATFORMS TO GENERATE</label><div className="platform-options">{(selectedIntent?.target_platforms ?? []).map(platform=><label key={platform}><input type="checkbox" checked={targetPlatforms.includes(platform)} onChange={e=>setTargetPlatforms(old=>e.target.checked?[...old,platform]:old.filter(x=>x!==platform))}/>{platform}</label>)}</div>
              <button className="primary-action" disabled={generating||!selectedIntentId||targetPlatforms.length===0} onClick={generateRules}><Sparkles size={15}/>{generating?"Generating…":"Generate detection candidates"}</button>
              <p className="muted">Requires OPENAI_API_KEY on the backend. Generation never approves or deploys a rule.</p>
            </div>
          </article>
        </section>
        <section className="panel intel-panel"><div className="panelhead"><div><b>Generated rule candidates</b><p>Versioned drafts with deterministic static-check results</p></div><span>{candidates.length} candidates</span></div>
          {candidates.length ? candidates.map(candidate=><article className="candidate-card" key={candidate.id}>
            <div className="candidate-title"><div><b>{candidate.name}</b><small>{candidate.platform.toUpperCase()} · VERSION {candidate.version} · {candidate.generator}</small></div><span className={candidate.validation_status==="failed"?"feed-fail":"feed-ok"}>{candidate.validation_status.replaceAll("_"," ")}</span></div>
            <pre>{candidate.query}</pre>
            {[...candidate.validation_report.errors,...candidate.validation_report.warnings].map((item,index)=><p className="validation-note" key={item.code+index}><AlertTriangle size={13}/><b>{item.code}</b> — {item.message}</p>)}
            <small className="muted">Status: {candidate.status} · Deployable: No — analyst approval and vendor validation remain required.</small>
          </article>) : <p className="no-data">No candidates yet. Save a detection intent and generate the first draft.</p>}
        </section>
      </> : page === "Validation" || page === "Review queue" || page === "Rule library" ? <>
        <section className="banner"><ShieldCheck/><div><b>{page}</b><p>Candidate queries and static validation results. Approval and production export are not enabled yet.</p></div><span>READ ONLY</span></section>
        <section className="panel intel-panel"><div className="panelhead"><div><b>Candidate inventory</b><p>Select an intent to inspect its candidates.</p></div><span>{candidates.length} candidates</span></div>
          <select className="intent-select" value={selectedIntentId} onChange={e=>setSelectedIntentId(e.target.value)}><option value="">Select intent</option>{intents.map(item=><option key={item.id} value={item.id}>{item.title}</option>)}</select>
          {candidates.map(candidate=><article className="candidate-card" key={candidate.id}><div className="candidate-title"><div><b>{candidate.name}</b><small>{candidate.platform.toUpperCase()} · V{candidate.version}</small></div><span>{candidate.validation_status}</span></div><pre>{candidate.query}</pre><small className="muted">Not approved · Not deployable</small></article>)}
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
