import { useCallback, useEffect, useState } from "react";
import {
  Activity, AlertTriangle, ArrowUpRight, BrainCircuit, CheckCircle2, ChevronRight,
  Database, FileSearch, Layers3, LoaderCircle, Network, Radar, RefreshCw, ShieldCheck,
  ShieldEllipsis, Sparkles, Search, Newspaper
} from "lucide-react";


const DATA_ROOT = `${import.meta.env.BASE_URL}data/`;
const readData = async (name: string) => {
  const response = await fetch(DATA_ROOT + name);
  if (!response.ok) throw new Error(`Unable to load ${name}`);
  return response.json();
};
const readAllIndicators = async () => {
  const [live, ...history] = await Promise.all([
    readData("indicators.json"),
    ...Array.from({ length: 11 }, (_, index) => readData(`indicators-history-${String(index + 1).padStart(2, "0")}.json`)),
  ]);
  const merged = new Map<string, any>();
  for (const item of [...history.flat(), ...live]) {
    const previous = merged.get(item.value);
    merged.set(item.value, {
      ...previous,
      ...item,
      sources: [...new Set([...(previous?.sources || []), ...(item.sources || [])].map((source: any) => typeof source === "string" ? source : source.name).filter(Boolean))],
      cvss_score: item.cvss_score ?? previous?.cvss_score ?? null,
    });
  }
  return [...merged.values()].map(item => ({
    ...item,
    created_at: item.created_at || item.last_seen || item.date_added || new Date().toISOString(),
    cvss_score: item.cvss_score ?? null,
  }));
};
const localApi = async (path: string, init?: RequestInit): Promise<Response> => {
  if (init?.method && init.method.toUpperCase() !== "GET") {
    return new Response(JSON.stringify({ detail: "ThreatWeave Portfolio is a static, read-only deployment. Data refreshes run through GitHub Actions; browser-side writes are not enabled." }), { status: 501, headers: { "Content-Type": "application/json" } });
  }
  let data: any = [];
  if (path.includes("/intelligence/summary")) { const summary = await readData("summary.json"); const all = await readAllIndicators(); data = { ...summary, indicators_total: all.length, active_indicators: all.filter((item: any) => item.status === "active").length, sources_total: new Set(all.flatMap((item: any) => item.sources || [])).size }; }
  else if (path.includes("/intelligence/indicators")) data = await readAllIndicators();
  else if (path.includes("/intelligence/feeds")) data = await readData("feeds.json");
  else if (path.includes("/intelligence/attack-techniques")) data = await readData("attack-techniques.json");
  else if (path.includes("/detection-intents") && !path.includes("/candidates")) data = await readData("detection-intents.json");
  else if (path.includes("/intelligence/pipeline/runs")) data = await readData("pipeline-runs.json");
  else if (path.includes("/intelligence/threat-graph")) {
    const graph = await readData("threat-graph.json");
    data = { nodes: graph.nodes || [], edges: (graph.edges || []).map((edge: any) => ({ ...edge, source: edge.source_entity_id, target: edge.target_entity_id })), truncated: false };
  } else if (path.includes("/intelligence/detection-opportunities")) data = [];
  else if (path.includes("/intelligence/cyber-news")) data = [];
  else if (path.includes("/detection-effectiveness")) data = null;
  else if (path.includes("/rules/") && path.includes("/test-runs")) data = [];
  else if (path.includes("/detection-intents/") && path.includes("/candidates")) {
    const id = path.split("/detection-intents/")[1]?.split("/")[0];
    const batches = await Promise.all(Array.from({ length: 6 }, (_, index) => readData(`rules-${index + 1}.json`)));
    data = batches.flat().filter((item: RuleCandidate) => item.intent_id === id);
  } else if (path.includes("/rules")) {
    const batches = await Promise.all(Array.from({ length: 6 }, (_, index) => readData(`rules-${index + 1}.json`)));
    data = batches.flat();
  }
  return new Response(JSON.stringify(data), { status: 200, headers: { "Content-Type": "application/json" } });
};

type Summary = { indicators_total: number; active_indicators: number; sources_total: number; latest_run: { source: string; status: string; started_at: string; records_seen: number; indicators_created: number } | null };
type Indicator = { id: string; indicator_type: string; value: string; confidence: number; severity: string; status: string; description: string | null; tags: string[]; sources: string[]; cvss_score: number | null; created_at: string };
type Feed = { name: string; status: string; last_run: string; records_seen: number; indicators_created: number };
type DetectionIntent = { id: string; title: string; description: string; behavior: string; severity: string; target_platforms: string[]; attack_techniques?: string[]; status: string };
type TestRun = { id:string; status:string; total_cases:number; passed_cases:number; failed_cases:number; case_results:{name:string;scenario_type:string;status:string;checks:{operator:string;value:string;passed:boolean}[]}[]; regression_report:{status:string;regressions:string[];improvements:string[]} };
type RuleCandidate = { id: string; intent_id: string; name: string; platform: string; query: string; version: number; status: string; validation_status: string; validation_report: { errors: {code:string;message:string}[]; warnings: {code:string;message:string}[]; is_deployable: boolean; telemetry_coverage?: {score:number|null;status:string;matched_requirements:number;total_requirements:number} }; generation_metadata: {provider?:string;model?:string;prompt_version?:string;generated_at?:string;validation_scope?:string;indicator_type?:string;indicator_count?:number}; generator: string };
type AttackTechnique = { id: string; external_id: string; name: string; description: string; platforms: string[]; tactics: string[]; is_subtechnique: boolean; revoked: boolean; deprecated: boolean; source_url: string };
type PipelineRun = { run_id: string; status: string; trigger: string; indicators_enriched: number; opportunities_found: number; candidates_created: number; candidates_skipped: number; started_at: string; completed_at: string | null; error_message: string | null; stage_results: Record<string, {status: string; reason?: string; error?: string}> };
type ThreatNode = { id: string; entity_type: string; external_id: string; name: string; description?: string; impact: string | null; source_name: string; source_reference: string; source_url: string | null; revoked: boolean; deprecated: boolean };
type ThreatEdge = { id: string; source: string; target: string; relationship_type: string; assertion_status: string; source_name: string; source_reference: string; source_url: string | null };
type ThreatGraph = { nodes: ThreatNode[]; edges: ThreatEdge[]; truncated: boolean };
type CyberNews = { id:string; headline:string; summary:string; impact:string; severity:string; source:string; url:string; published_at:string };
type Opportunity = { intent_id: string; title: string; severity: string; status: string; target_platforms: string[]; association_type: string; indicators: { indicator_id: string; indicator_type: string; value: string; confidence: number; severity: string; freshness: string; evidence_count: number }[]; matched_techniques: string[]; matched_cves: string[]; indicator_count: number; evidence_count: number; rationale: string };

const LOCAL_INTENTS_KEY = "threatweave:local-detection-intents:v1";
const LOCAL_RULES_KEY = "threatweave:local-rule-drafts:v1";
const readBrowserDrafts = <T,>(key: string): T[] => {
  try {
    if (typeof window === "undefined") return [];
    const value = window.localStorage.getItem(key);
    return value ? JSON.parse(value) as T[] : [];
  } catch { return []; }
};
const writeBrowserDrafts = <T,>(key: string, value: T[]) => {
  if (typeof window === "undefined") throw new Error("Browser storage is unavailable.");
  window.localStorage.setItem(key, JSON.stringify(value));
};
const buildLocalQueries = (intent: DetectionIntent, platform: string, version: number): RuleCandidate => {
  const terms = [...new Set((intent.title + " " + intent.description + " " + intent.behavior).toLowerCase().match(/[a-z0-9]{3,}/g) || [])
    .filter(word => !["the","and","for","with","that","this","from","when","into","should","detect","detection","activity","system","using"].includes(word))].slice(0, 8);
  const safe = (value: string) => value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const quoted = terms.map(safe);
  let query = "";
  if (platform === "splunk") {
    query = 'index=YOUR_INDEX sourcetype=YOUR_PROCESS_TELEMETRY\n| eval searchable=lower(coalesce(process_name,"")." ".coalesce(command_line,"")." ".coalesce(parent_process_name,""))\n| where ' +
      (quoted.length ? quoted.map(term => 'like(searchable, "%' + term + '%")').join(" OR ") : "isnotnull(process_name)") +
      '\n| table _time host user process_name parent_process_name command_line destination_ip\n| sort - _time\n| head 200';
  } else if (platform === "sentinel") {
    query = '// Replace table/field names to match your Sentinel connectors.\nDeviceProcessEvents\n| extend SearchText = tolower(strcat(ProcessCommandLine, " ", FileName, " ", InitiatingProcessFileName))\n| where ' +
      (quoted.length ? quoted.map(term => 'SearchText contains "' + term + '"').join(" or ") : "isnotempty(ProcessCommandLine)") +
      '\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName\n| order by Timestamp desc';
  } else if (platform === "chronicle") {
    query = '// YARA-L 2.0 starter. Confirm UDM fields and event types for your tenant.\nrule threatweave_' + intent.id.replace(/[^a-zA-Z0-9_]/g, "_").slice(-24) + ' {\n  meta:\n    author = "ThreatWeave"\n    description = "' + safe(intent.title) + '"\n    severity = "' + safe(intent.severity) + '"\n  events:\n    $e.metadata.event_type = "PROCESS_LAUNCH"\n' +
      (quoted.length ? quoted.map(term => '    $e.principal.process.command_line = /(?i)' + term + '/').join("\n") : '    $e.principal.process.command_line != ""') +
      '\n  condition:\n    $e\n}';
  } else {
    query = 'title: "' + safe(intent.title) + '"\nid: ' + intent.id + '\nstatus: experimental\ndescription: "' + safe(intent.description || intent.behavior || "Review and tune this detection for your telemetry.") + '"\nauthor: ThreatWeave\ndate: ' + new Date().toISOString().slice(0, 10) +
      '\ntags:\n  - attack.' + (intent.attack_techniques?.[0] || "tactic_id_unknown").toLowerCase() +
      '\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains:\n' +
      (quoted.length ? quoted : ["REPLACE_WITH_BEHAVIOR_KEYWORD"]).map(term => '      - "' + term + '"').join("\n") +
      '\n  condition: selection\nfalsepositives:\n  - Legitimate administrative activity\nlevel: medium';
  }
  return {
    id: "local-" + intent.id + "-" + platform + "-v" + version, intent_id: intent.id,
    name: intent.title + " · " + platform, platform, query, version,
    status: "draft", validation_status: "not_validated",
    validation_report: { errors: [], warnings: [{ code: "template_review_required", message: "Starter template only. Map fields, validate syntax and test against representative telemetry before deployment." }], is_deployable: false, telemetry_coverage: { score: null, status: "not_assessed", matched_requirements: 0, total_requirements: 0 } },
    generation_metadata: { provider: "local-template", model: "deterministic-browser-template", prompt_version: "1", generated_at: new Date().toISOString(), validation_scope: "not_validated" },
    generator: "browser-template",
  };
};


const nav = [
  { label: "Overview", icon: Layers3 },
  { label: "Threat intelligence", icon: Radar },
  { label: "Cyber news", icon: Newspaper },
  { label: "Correlation", icon: BrainCircuit },
  { label: "Threat graph", icon: Network },
  { label: "ATT&CK catalog", icon: ShieldCheck },
  { label: "Rule generator", icon: Sparkles },
  { label: "Rule library", icon: Database },
];

function App() {
  const [page, setPage] = useState("Overview");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [cyberNews, setCyberNews] = useState<CyberNews[]>([]);
  const [newsSeverity, setNewsSeverity] = useState("");
  const [newsSource, setNewsSource] = useState("");
  const [newsWindow, setNewsWindow] = useState("7d");
  const [loadingNews, setLoadingNews] = useState(false);
  const [newsFetchedAt, setNewsFetchedAt] = useState("");
  const [newsErrors, setNewsErrors] = useState<string[]>([]);
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [query, setQuery] = useState("");
  const [intelWindow, setIntelWindow] = useState("7d");
  const [intelImpact, setIntelImpact] = useState("");
  const [intelSeverity, setIntelSeverity] = useState("");
  const [intelType, setIntelType] = useState("");
  const [intelStatus, setIntelStatus] = useState("");
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [syncingNvd, setSyncingNvd] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [intents, setIntents] = useState<DetectionIntent[]>([]);
  const [candidates, setCandidates] = useState<RuleCandidate[]>([]);
  const [testSuiteJson, setTestSuiteJson] = useState(JSON.stringify({cases:[{name:"Required process telemetry",scenario_type:"positive",fixture:{process_name:"powershell.exe"},assertions:[{operator:"contains",value:"process_name"}]}]},null,2));
  const [testRuns, setTestRuns] = useState<Record<string,TestRun>>({});
  const [runningTests, setRunningTests] = useState<Record<string,boolean>>({});
  const [selectedIntentId, setSelectedIntentId] = useState("");
  const [intentTitle, setIntentTitle] = useState("");
  const [intentDescription, setIntentDescription] = useState("");
  const [intentBehavior, setIntentBehavior] = useState("");
  const [attackTechniqueIds, setAttackTechniqueIds] = useState("");
  const [targetPlatforms, setTargetPlatforms] = useState<string[]>(["splunk", "sentinel", "chronicle", "sigma"]);
  const [creatingIntent, setCreatingIntent] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [attackTechniques, setAttackTechniques] = useState<AttackTechnique[]>([]);
  const [attackSearch, setAttackSearch] = useState("");
  const [attackTacticFilter, setAttackTacticFilter] = useState("");
  const [attackTechniqueFilter, setAttackTechniqueFilter] = useState("");
  const [libraryVersionSelection, setLibraryVersionSelection] = useState<Record<string, number>>({});
  const [syncingAttack, setSyncingAttack] = useState(false);
  const [uploadingCsv, setUploadingCsv] = useState(false);
  const [libraryQuery, setLibraryQuery] = useState("");
  const [libraryPlatform, setLibraryPlatform] = useState("");
  const [libraryValidation, setLibraryValidation] = useState("");
  const [libraryTactic, setLibraryTactic] = useState("");
  const [libraryTechnique, setLibraryTechnique] = useState("");
  const [libraryOffset, setLibraryOffset] = useState(0);
  const [opportunities, setOpportunities] = useState<Opportunity[]>([]);
  const [loadingOpportunities, setLoadingOpportunities] = useState(false);
  const [threatGraph, setThreatGraph] = useState<ThreatGraph>({ nodes: [], edges: [], truncated: false });
  const [loadingThreatGraph, setLoadingThreatGraph] = useState(false);
  const [stixImporting, setStixImporting] = useState(false);
  const [entityTypeFilter, setEntityTypeFilter] = useState("");
  const [entitySearch, setEntitySearch] = useState("");
  const [graphStatusFilter, setGraphStatusFilter] = useState("all");
  const [selectedGraphNodeId, setSelectedGraphNodeId] = useState("");
  const [pipelineRuns, setPipelineRuns] = useState<PipelineRun[]>([]);
  const [pipelineQueued, setPipelineQueued] = useState(false);
  const [effectiveness, setEffectiveness] = useState<any>(null);
  const [loadingEffectiveness, setLoadingEffectiveness] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [s, i, f] = await Promise.all([
        localApi(`/api/v1/intelligence/summary`),
        localApi(`/api/v1/intelligence/indicators?limit=500`),
        localApi(`/api/v1/intelligence/feeds`),
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
      const response = await localApi(`/api/v1/intelligence/feeds/cisa-kev/sync`, { method: "POST" });
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
      const response = await localApi(`/api/v1/intelligence/feeds/custom/csv`, {
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
      const response = await localApi(`/api/v1/intelligence/attack-techniques?limit=500`);
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
      const response = await localApi(`/api/v1/intelligence/feeds/mitre-attack/sync`, { method: "POST" });
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
      const response = await localApi(`/api/v1/detection-intents?limit=100`);
      if (!response.ok) throw new Error("Unable to load detection intents.");
      const items: DetectionIntent[] = await response.json();
      const mergedIntents = [...readBrowserDrafts<DetectionIntent>(LOCAL_INTENTS_KEY), ...items].filter((item, index, all) => all.findIndex(other => other.id === item.id) === index);
      setIntents(mergedIntents);
      if (page === "Rule library") {
        const rulesResponse = await localApi(`/api/v1/rules?limit=100&offset=${libraryOffset}`);
        if (!rulesResponse.ok) throw new Error("Unable to load the rule library.");
        const staticRules: RuleCandidate[] = await rulesResponse.json();
        const localRules = readBrowserDrafts<RuleCandidate>(LOCAL_RULES_KEY);
        setCandidates([...localRules, ...staticRules].filter((item, index, all) => all.findIndex(other => other.id === item.id) === index));
        return;
      }
      const currentId = selectedIntentId || items[0]?.id || "";
      if (!selectedIntentId && currentId) setSelectedIntentId(currentId);
      if (currentId) {
        const rulesResponse = await localApi(`/api/v1/detection-intents/${currentId}/candidates`);
        if (!rulesResponse.ok) throw new Error("Unable to load rule candidates.");
        const loadedCandidates: RuleCandidate[] = await rulesResponse.json();
        const localRules = readBrowserDrafts<RuleCandidate>(LOCAL_RULES_KEY).filter(item => item.intent_id === currentId);
        setCandidates([...localRules, ...loadedCandidates].filter((item, index, all) => all.findIndex(other => other.id === item.id) === index));
        const history = await Promise.all(loadedCandidates.slice(0, 20).map(async candidate => {
          const response = await localApi(`/api/v1/rules/${candidate.id}/test-runs`);
          if (!response.ok) return null;
          const runs: TestRun[] = await response.json();
          return runs.length ? [candidate.id, runs[0]] as const : null;
        }));
        setTestRuns(current => ({
          ...current,
          ...Object.fromEntries(history.filter((item): item is readonly [string, TestRun] => item !== null)),
        }));
      } else setCandidates([]);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load detection engineering data.");
    }
  }, [selectedIntentId, page, libraryOffset]);

  useEffect(() => {
    if (page === "Rule generator" || page === "Rule library") void loadDetectionData();
  }, [page, loadDetectionData]);


  const createIntent = async () => {
    const title = intentTitle.trim();
    if (!title) { setError("Add a detection name before saving."); return; }
    if (!intentDescription.trim() && !intentBehavior.trim()) { setError("Add a description or behavior so the query templates have useful context."); return; }
    if (!targetPlatforms.length) { setError("Select at least one query language."); return; }
    setCreatingIntent(true); setError(""); setNotice("");
    try {
      const intent: DetectionIntent = {
        id: "local-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 8),
        title, description: intentDescription.trim(), behavior: intentBehavior.trim(),
        severity: "medium", target_platforms: [...targetPlatforms],
        attack_techniques: attackTechniqueIds.split(",").map(value => value.trim().toUpperCase()).filter(Boolean),
        status: "draft",
      };
      const saved = readBrowserDrafts<DetectionIntent>(LOCAL_INTENTS_KEY);
      writeBrowserDrafts(LOCAL_INTENTS_KEY, [intent, ...saved.filter(item => item.id !== intent.id)]);
      setIntents(current => [intent, ...current.filter(item => item.id !== intent.id)]);
      setIntentTitle(""); setIntentDescription(""); setIntentBehavior(""); setAttackTechniqueIds("");
      setSelectedIntentId(intent.id);
      setNotice("Detection intent saved in this browser. It remains available on this device and browser; it is not synced to a shared server.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to save this intent in browser storage.");
    } finally { setCreatingIntent(false); }
  };

  const generateRules = async () => {
    const intent = intents.find(item => item.id === selectedIntentId);
    if (!intent) { setError("Select or save a detection intent first."); return; }
    if (!targetPlatforms.length) { setError("Select at least one query language."); return; }
    setGenerating(true); setError(""); setNotice("");
    try {
      const existing = readBrowserDrafts<RuleCandidate>(LOCAL_RULES_KEY);
      const generated = targetPlatforms.map(platform => {
        const latest = [...existing, ...candidates].filter(item => item.intent_id === intent.id && item.platform === platform).reduce((max, item) => Math.max(max, item.version || 0), 0);
        return buildLocalQueries(intent, platform, latest + 1);
      });
      writeBrowserDrafts(LOCAL_RULES_KEY, [...generated, ...existing.filter(item => !generated.some(next => next.id === item.id))]);
      setCandidates(current => [...generated, ...current.filter(item => !generated.some(next => next.id === item.id))]);
      setNotice(generated.length + " query draft(s) generated locally. Review field mappings, syntax and telemetry before using them in production.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to save generated queries in browser storage.");
    } finally { setGenerating(false); }
  };

  const loadRuleLibrary = useCallback(async () => {
    try {
      const params = new URLSearchParams({ limit: "500", offset: String(libraryOffset) });
      if (libraryQuery.trim()) params.set("q", libraryQuery.trim());
      if (libraryPlatform) params.set("platform", libraryPlatform);
      if (libraryValidation) params.set("validation_status", libraryValidation);
      const response = await localApi(`/api/v1/rules?${params.toString()}`);
      if (!response.ok) throw new Error("Unable to load the rule library.");
      setCandidates(await response.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load the rule library.");
    }
  }, [libraryQuery, libraryPlatform, libraryValidation, libraryOffset]);

  useEffect(() => {
    if (page === "Rule library") {
      void (async () => {
        await Promise.all([loadDetectionData(), loadAttackCatalog()]);
        await loadRuleLibrary();
      })();
    }
  }, [page, loadRuleLibrary, loadDetectionData, loadAttackCatalog]);

  const runCandidateTests = async (candidateId: string) => {
    setRunningTests(current => ({...current,[candidateId]:true}));
    setError(""); setNotice("");
    try {
      const suite = JSON.parse(testSuiteJson);
      const response = await localApi(`/api/v1/rules/${candidateId}/test-runs`, {
        method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(suite),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Unable to run offline test suite.");
      setTestRuns(current => ({...current,[candidateId]:body}));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Invalid test suite JSON or test run failed.");
    } finally {
      setRunningTests(current => ({...current,[candidateId]:false}));
    }
  };

  const loadOpportunities = useCallback(async () => {
    setLoadingOpportunities(true);
    try {
      const response = await localApi(`/api/v1/intelligence/detection-opportunities?limit=100`);
      if (!response.ok) throw new Error("Unable to load detection opportunities.");
      setOpportunities(await response.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load detection opportunities.");
    } finally {
      setLoadingOpportunities(false);
    }
  }, []);

  useEffect(() => {
    if (page === "Correlation") void loadOpportunities();
  }, [page, loadOpportunities]);

  const loadEffectiveness = useCallback(async () => {
    setLoadingEffectiveness(true);
    try {
      const response = await localApi(`/api/v1/detection-effectiveness`);
      if (!response.ok) throw new Error("Unable to load detection effectiveness metrics.");
      setEffectiveness(await response.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load detection effectiveness metrics.");
    } finally {
      setLoadingEffectiveness(false);
    }
  }, []);

  useEffect(() => {
    if (page === "Effectiveness") void loadEffectiveness();
  }, [page, loadEffectiveness]);

  const loadPipelineRuns = useCallback(async () => {
    try {
      const response = await localApi(`/api/v1/intelligence/pipeline/runs?limit=10`);
      if (!response.ok) throw new Error("Unable to load pipeline history.");
      setPipelineRuns(await response.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load pipeline history.");
    }
  }, []);

  useEffect(() => {
    if (page === "Threat intelligence") void loadPipelineRuns();
  }, [page, loadPipelineRuns]);

  const loadCyberNews = useCallback(async () => {
    setLoadingNews(true);
    try {
      const response = await localApi(`/api/v1/intelligence/cyber-news?limit=100`);
      if (!response.ok) throw new Error("Unable to load cyber news.");
      const body = await response.json();
      setCyberNews(body.items || []);
      setNewsFetchedAt(body.fetched_at || "");
      setNewsErrors(body.sources_failed || []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load cyber news.");
    } finally {
      setLoadingNews(false);
    }
  }, []);

  useEffect(() => {
    if (page === "Cyber news") void loadCyberNews();
  }, [page, loadCyberNews]);

  const startPipeline = async () => {
    setPipelineQueued(true); setError(""); setNotice("");
    try {
      const response = await localApi(`/api/v1/intelligence/pipeline/runs`, { method: "POST" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Unable to queue intelligence pipeline.");
       setNotice("Full intelligence pipeline started in the API background. Refresh run history to follow progress.");
      await loadPipelineRuns();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to queue intelligence pipeline.");
    } finally {
      setPipelineQueued(false);
    }
  };

  const loadThreatGraph = useCallback(async () => {
    setLoadingThreatGraph(true);
    try {
      const response = await localApi(`/api/v1/intelligence/threat-graph?limit=500`);
      if (!response.ok) throw new Error("Unable to load threat graph.");
      setThreatGraph(await response.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load threat graph.");
    } finally {
      setLoadingThreatGraph(false);
    }
  }, []);

  useEffect(() => {
    if (page === "Threat graph") void loadThreatGraph();
  }, [page, loadThreatGraph]);

  const importStix = async (file?: File) => {
    if (!file) return;
    setStixImporting(true); setError(""); setNotice("");
    try {
      const bundle = JSON.parse(await file.text());
      const response = await localApi(`/api/v1/intelligence/feeds/custom/stix`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source_name: file.name.slice(0, 100), bundle }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "STIX import failed.");
      setNotice(`STIX import complete — ${body.entities_created} entities and ${body.relationships_created} relationships created; ${body.objects_skipped} objects skipped.`);
      await loadThreatGraph();
    } catch (e) {
      setError(e instanceof Error ? e.message : "STIX import failed. Check that the file is valid JSON.");
    } finally {
      setStixImporting(false);
    }
  };

  const selectedIntent = intents.find((item) => item.id === selectedIntentId);
  const syncNvd = async () => {
    setSyncingNvd(true); setError(""); setNotice("");
    try {
      const response = await localApi(`/api/v1/intelligence/feeds/nvd/sync`, { method: "POST" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "NVD sync failed.");
      setNotice(`NVD sync complete — ${body.records_seen.toLocaleString()} records checked, ${body.indicators_created.toLocaleString()} new indicators added.${body.complete_window ? "" : " The result window was larger than one page; another sync is needed to complete it."}`);
      await loadData();
    } catch (e) {
      setError(e instanceof Error ? e.message : "NVD sync failed.");
    } finally { setSyncingNvd(false); }
  };

  const filtered = indicators.filter((item) => {
    const created = new Date(item.created_at).getTime();
    const age = Date.now() - created;
    const inWindow = intelWindow === "24h" ? age <= 24*60*60*1000 : intelWindow === "7d" ? age <= 7*24*60*60*1000 : true;
    const impact = ["critical","high"].includes(item.severity.toLowerCase()) ? "high" : item.severity.toLowerCase() === "medium" ? "medium" : "low";
    return inWindow && (!intelImpact || impact === intelImpact) &&
      (!intelSeverity || item.severity.toLowerCase() === intelSeverity) &&
      (!intelType || item.indicator_type.toLowerCase() === intelType) &&
      (!intelStatus || item.status.toLowerCase() === intelStatus) &&
      (item.value.toLowerCase().includes(query.toLowerCase()) || (item.description || "").toLowerCase().includes(query.toLowerCase()));
  });
  const graphVisibleNodes = threatGraph.nodes.filter(node => {
    const status = node.revoked ? "revoked" : node.deprecated ? "deprecated" : "current";
    return (!entityTypeFilter || node.entity_type === entityTypeFilter) &&
      (!graphStatusFilter || graphStatusFilter === "all" || status === graphStatusFilter) &&
      (`${node.name} ${node.external_id} ${node.source_name}`.toLowerCase().includes(entitySearch.toLowerCase()));
  });
  const graphVisibleIds = new Set(graphVisibleNodes.map(node => node.id));
  const graphVisibleEdges = threatGraph.edges.filter(edge => graphVisibleIds.has(edge.source) && graphVisibleIds.has(edge.target));
  const graphTypeCounts = Object.entries(graphVisibleNodes.reduce<Record<string, number>>((counts, node) => {
    counts[node.entity_type] = (counts[node.entity_type] || 0) + 1;
    return counts;
  }, {})).sort((a, b) => b[1] - a[1]);
  const graphConnectedCounts = graphVisibleNodes.map(node => ({
    ...node,
    connections: graphVisibleEdges.filter(edge => edge.source === node.id || edge.target === node.id).length,
  })).sort((a, b) => b.connections - a.connections).slice(0, 5);
  const selectedGraphNode = graphVisibleNodes.find(node => node.id === selectedGraphNodeId) || null;
  const selectedGraphEdges = selectedGraphNode ? graphVisibleEdges.filter(edge => edge.source === selectedGraphNode.id || edge.target === selectedGraphNode.id) : [];
  const visibleAttackTechniques = attackTechniques.filter(item =>
    (!attackTacticFilter || item.tactics.includes(attackTacticFilter)) &&
    (!attackTechniqueFilter || item.external_id === attackTechniqueFilter) &&
    [item.external_id, item.name, item.description, ...item.tactics, ...item.platforms].join(" ").toLowerCase().includes(attackSearch.toLowerCase())
  );
  const filteredLibraryCandidates = candidates.filter(candidate => {
    const intent = intents.find(x => x.id === candidate.intent_id);
    const techniques = intent?.attack_techniques || [];
    const tacticMatch = !libraryTactic || techniques.some(id => attackTechniques.some(t => t.external_id === id && t.tactics.includes(libraryTactic)));
    const techniqueMatch = !libraryTechnique || techniques.includes(libraryTechnique);
    const queryMatch = !libraryQuery || candidate.name.toLowerCase().includes(libraryQuery.toLowerCase()) || candidate.query.toLowerCase().includes(libraryQuery.toLowerCase());
    const platformMatch = !libraryPlatform || candidate.platform === libraryPlatform;
    return tacticMatch && techniqueMatch && queryMatch && platformMatch;
  });
  const libraryGroups = Object.values(filteredLibraryCandidates.reduce<Record<string, { key: string; title: string; subtitle: string; candidates: RuleCandidate[] }>>((groups, candidate) => {
    const intent = intents.find(x => x.id === candidate.intent_id);
    const rawTitle = intent?.title || candidate.name;
    const iocBatch = rawTitle.match(/^ThreatWeave Active IOC Coverage:\s*([a-z0-9_-]+):(\d+)$/i);
    const kind = iocBatch?.[1].toLowerCase();
    const names: Record<string,string> = {
      cve: "Vulnerability Exposure Monitoring",
      "cve-cwe-79": "Cross-Site Scripting Vulnerability Detection",
      "cve-cwe-89": "SQL Injection Vulnerability Detection",
      "cve-cwe-78": "OS Command Injection Vulnerability Detection",
      "cve-cwe-22": "Path Traversal Vulnerability Detection",
      "cve-cwe-352": "Cross-Site Request Forgery Vulnerability Detection",
      "cve-cwe-287": "Authentication Weakness Monitoring",
      "cve-cwe-862": "Authorization Weakness Monitoring",
      "cve-cwe-200": "Sensitive Information Exposure Monitoring",
      "cve-cwe-416": "Use-After-Free Vulnerability Detection",
      "cve-cwe-787": "Out-of-Bounds Write Vulnerability Detection",
      "cve-cwe-125": "Out-of-Bounds Read Vulnerability Detection",
      "cve-cwe-476": "Null Pointer Dereference Vulnerability Detection",
      "cve-cwe-20": "Input Validation Vulnerability Detection",
      "cve-cwe-94": "Code Injection Vulnerability Detection",
      "cve-cwe-434": "Unrestricted File Upload Vulnerability Detection",
      "cve-cwe-502": "Unsafe Deserialization Vulnerability Detection",
      "cve-cwe-269": "Privilege Management Weakness Monitoring",
      "cve-cwe-798": "Hard-Coded Credential Vulnerability Detection",
      "cve-unclassified": "Unclassified CVE Vulnerability Monitoring",
      ip: "Suspicious IP Communication",
      ipv4: "Suspicious IP Communication",
      ipv6: "Suspicious IP Communication",
      domain: "Malicious Domain Infrastructure",
      hostname: "Malicious Hostname Monitoring",
      url: "Malicious URL Access",
      hash: "Known Malicious File Detection",
      file_hash: "Known Malicious File Detection",
    };
    const key = kind ? `ioc::${kind}` : candidate.intent_id + "::" + candidate.name;
    const title = kind ? (names[kind] || (kind.startsWith("cve-cwe-") ? `CVE Weakness Group · ${kind.replace("cve-cwe-","CWE-").toUpperCase()}` : `${kind.toUpperCase()} Indicator Monitoring`)) : rawTitle;
    const subtitle = kind ? `Grouped active ${kind.toUpperCase()} indicators · separate batches and language versions` : (intent?.description || candidate.name);
    if (!groups[key]) groups[key] = { key, title, subtitle, candidates: [] };
    groups[key].candidates.push(candidate);
    return groups;
  }, {}));
  const latestGeneratedCandidates = Object.values(candidates.reduce<Record<string, RuleCandidate>>((latest, candidate) => {
    if (!latest[candidate.platform] || candidate.version > latest[candidate.platform].version) latest[candidate.platform] = candidate;
    return latest;
  }, {}));


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
      <div className="sidebottom"><span className="live-dot"/> Static snapshot<hr/><div className="user"><b>SE</b><div>Team member<small>Workspace access</small></div></div></div>
    </aside>
    <main>
      <header><span>Workspace　›　<b>{page}</b></span><small><span className="live-dot"/> STATIC PORTFOLIO</small></header>
      <section className="heading">
        <div><label>DETECTION ENGINEERING WORKSPACE</label><h1>{page === "Threat intelligence" ? "Threat Intelligence Center" : page === "ATT&CK catalog" ? "MITRE ATT&CK Catalog" : page === "Rule generator" ? "Detection Rule Generator" : page === "Correlation" ? "Intelligence Correlation" : page === "Threat graph" ? "Threat Entity Graph" : page === "Cyber news" ? "Cyber News & Security Briefing" : "Good morning, team 👋"}</h1><p>Monitor threat intelligence, preserve source evidence, and prepare trusted inputs for detection engineering.</p></div>
        {page === "Threat intelligence" && <div className="feed-actions"><button disabled title="Available in a backend deployment"><Network size={16} className={pipelineQueued ? "spin" : ""}/>{pipelineQueued ? "Queueing…" : "Run full pipeline"}</button><button disabled title="Scheduled refresh runs daily through GitHub Actions"><RefreshCw size={16} className={syncing ? "spin" : ""}/>{syncing ? "Syncing CISA…" : "Sync CISA KEV"}</button><button disabled title="NVD is not part of the current static refresh"><RefreshCw size={16} className={syncingNvd ? "spin" : ""}/>{syncingNvd ? "Syncing NVD…" : "Sync NVD CVEs"}</button><label className="upload-button" aria-disabled="true" title="CSV import requires a backend">CSV import unavailable<input type="file" accept=".csv,text/csv" disabled onChange={e=>{const input=e.currentTarget;const file=input.files?.[0];input.value="";if(file)void importCsv(file);}}/></label></div>}
        {page === "ATT&CK catalog" && <button disabled title="ATT&CK refresh runs daily through GitHub Actions"><RefreshCw size={16} className={syncingAttack ? "spin" : ""}/>{syncingAttack ? "Syncing catalog…" : "Sync ATT&CK"}</button>}
      </section>
      <div className="notice"><AlertTriangle size={16}/> Portfolio snapshot. Public CISA KEV and MITRE ATT&amp;CK data refresh daily at 08:00 IST. Detection intents and query drafts can be saved locally in this browser; they are not synced across devices. Shared storage, live ingestion and server-side testing require a backend.</div>\n      {error && <div className="notice error"><AlertTriangle size={16}/>{error}<button onClick={loadData}>Retry</button></div>}
      {notice && <div className="notice success"><CheckCircle2 size={16}/>{notice}</div>}
      {page === "Cyber news" ? <>
        <section className="banner"><Newspaper/><div><b>Cybersecurity headlines from trusted public sources</b><p>Short summaries, practical impact and severity labels to help you scan what matters.</p></div><span>NOT INCLUDED</span></section>
        <section className="panel intel-panel">
          <div className="panelhead"><div><b>Latest cyber news</b><p>{newsFetchedAt ? `Fetched ${new Date(newsFetchedAt).toLocaleString()}` : "Cyber-news ingestion is not included in this static release."}</p></div><button disabled title="Cyber-news ingestion requires a backend"><RefreshCw size={15} className={loadingNews?"spin":""}/> Refresh news</button></div>
          <div className="library-filters">
            <select value={newsWindow} onChange={e=>setNewsWindow(e.target.value)}><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="all">All fetched</option></select>
            <select value={newsSeverity} onChange={e=>setNewsSeverity(e.target.value)}><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
            <select value={newsSource} onChange={e=>setNewsSource(e.target.value)}><option value="">All sources</option>{[...new Set(cyberNews.map(x=>x.source))].sort().map(source=><option key={source} value={source}>{source}</option>)}</select>
          </div>
          <div className="news-legend"><span className="news-critical">Critical</span><span className="news-high">High</span><span className="news-medium">Medium</span><span className="news-low">Low</span><small>Severity is automatically classified from headline and article summary; verify the source for context.</small></div>
          {newsErrors.length>0&&<p className="muted">Some sources could not be reached: {newsErrors.join(" · ")}</p>}
          <div className="news-list">
            {cyberNews.filter(item=>{
              const age=Date.now()-new Date(item.published_at).getTime();
              const inWindow=newsWindow==="24h"?age<=86400000:newsWindow==="7d"?age<=7*86400000:true;
              return inWindow&&(!newsSeverity||item.severity===newsSeverity)&&(!newsSource||item.source===newsSource);
            }).map(item=><article className={`news-card severity-border-${item.severity}`} key={item.id}>
              <div className="news-card-top"><span className={`news-severity ${"news-"+item.severity}`}>{item.severity}</span><small>{new Date(item.published_at).toLocaleString()}</small></div>
              <h3><a href={item.url} target="_blank" rel="noreferrer">{item.headline}</a></h3>
              <div className="news-details"><div><label>WHAT HAPPENED</label><p>{item.summary}</p></div><div><label>IMPACT</label><p>{item.impact}</p></div></div>
              <div className="news-source"><span>SOURCE</span><a href={item.url} target="_blank" rel="noreferrer">{item.source} ↗</a></div>
            </article>)}
            {!loadingNews&&cyberNews.length===0&&<p className="no-data">No news could be loaded. Check backend connectivity and try refreshing.</p>}
            {!loadingNews&&cyberNews.length>0&&cyberNews.filter(item=>{const age=Date.now()-new Date(item.published_at).getTime();const inWindow=newsWindow==="24h"?age<=86400000:newsWindow==="7d"?age<=7*86400000:true;return inWindow&&(!newsSeverity||item.severity===newsSeverity)&&(!newsSource||item.source===newsSource);}).length===0&&<p className="no-data">No stories match these filters.</p>}
          </div>
        </section>
      </> : page === "Threat intelligence" ? <>
        <section className="banner"><Radar/><div><b>CISA Known Exploited Vulnerabilities</b><p>Daily public CISA KEV and MITRE ATT&CK snapshots with source attribution. CVSS is shown only when supplied by NVD.</p></div><span>{feeds.find(f => f.name === "CISA KEV")?.status?.toUpperCase() || "NOT SYNCED"}</span></section>
        <section className="stats">{stats.map(({ label, value, note, icon: Icon }) => <article key={label}><div>{label}<Icon size={18}/></div><strong>{loading ? "…" : value.toLocaleString?.() ?? value}</strong><small>{note}</small></article>)}</section>
        <section className="panel intel-panel">
          <div className="panelhead"><div><b>Indicator inventory</b><p>Quickly narrow current intelligence by recency, impact and status</p></div><span>{filtered.length} matching records</span></div>
          <div className="library-filters">
            <select value={intelWindow} onChange={e=>setIntelWindow(e.target.value)}><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="all">All time</option></select>
            <select value={intelImpact} onChange={e=>setIntelImpact(e.target.value)}><option value="">All impact levels</option><option value="high">High impact</option><option value="medium">Medium impact</option><option value="low">Low / unknown impact</option></select>
            <select value={intelSeverity} onChange={e=>setIntelSeverity(e.target.value)}><option value="">All severities</option>{["critical","high","medium","low","unknown"].map(v=><option key={v} value={v}>{v}</option>)}</select>
            <select value={intelType} onChange={e=>setIntelType(e.target.value)}><option value="">All types</option>{[...new Set(indicators.map(x=>x.indicator_type))].sort().map(v=><option key={v} value={v}>{v.toUpperCase()}</option>)}</select>
            <select value={intelStatus} onChange={e=>setIntelStatus(e.target.value)}><option value="">All statuses</option>{[...new Set(indicators.map(x=>x.status))].sort().map(v=><option key={v} value={v}>{v}</option>)}</select>
          </div>
          <small className="muted">Severity is source-provided or derived from CVSS. CVSS is the vulnerability base score (0–10), shown only when NVD provides it. Confidence is a feed-specific ingestion value, not a universal risk score. Impact is currently grouped from severity.</small>
          <div className="scoring-guide"><b>How severity and scores are identified</b>
            <span><strong>Severity</strong> NVD uses the CVSS baseSeverity label (CVSS v3/v4 bands: Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9; 0.0 is None). CISA KEV priority is labelled High when the feed flags known ransomware campaign use, otherwise Medium. This is an operational priority heuristic, not a CVSS severity assessment. This static portfolio refresh currently includes CISA KEV only; NVD CVSS is blank unless supplied by an NVD-backed record.</span>
            <span><strong>CVSS score</strong> The NVD CVSS baseScore (0–10) from CVSS v4.0, v3.1, v3.0 or v2 metrics. It is blank when no NVD score is available. It is not calculated by ThreatWeave.</span>
            <span><strong>Confidence</strong> Current configured feed values: NVD 90, CISA KEV 100, URLhaus 95, OpenPhish 85, SSLBL 90, Feodo 95. Custom CSV defaults to 50 if omitted. These are source-specific defaults, not a calibrated probability. Where multiple feeds contribute to one indicator, the stored indicator confidence is not separately calibrated per source.</span>
            <span><strong>Important</strong> Severity, CVSS and confidence are different fields. Do not compare confidence percentages as though they were vulnerability scores.</span>
          </div>
          <div className="searchbar"><Search size={16}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search CVE or description…"/><button onClick={loadData} title="Refresh"><RefreshCw size={15}/></button></div>
          <div className="table-wrap"><table><thead><tr><th>INDICATOR</th><th>TYPE</th><th>SOURCE</th><th>SEVERITY</th><th>CVSS</th><th>CONFIDENCE</th><th>STATUS</th></tr></thead><tbody>
            {filtered.map(item => <tr key={item.id}><td><b>{item.value}</b><small>{item.description || item.tags.join(" · ") || "No description supplied"}</small></td><td><span className="type-pill">{item.indicator_type.toUpperCase()}</span></td><td>{item.sources?.length?item.sources.map(source=><span className="source-chip" key={source}>{source}</span>):<span className="muted">Unknown</span>}</td><td><span className={`severity ${item.severity}`}>{item.severity}</span></td><td>{item.cvss_score===null||item.cvss_score===undefined?"—":item.cvss_score.toFixed(1)+"/10"}</td><td>{item.confidence}%</td><td><span className="status-pill">{item.status}</span></td></tr>)}
            {!loading && filtered.length === 0 && <tr><td colSpan={7} className="no-data">{query ? "No indicators match this search." : "No indicators yet. Sync a feed to populate the inventory."}</td></tr>}
          </tbody></table></div>
        </section>
        <section className="panel feed-panel"><div className="panelhead"><div><b>Automated pipeline history</b><p>Feed ingestion, enrichment, correlation and draft candidate generation</p></div><button onClick={loadPipelineRuns}><RefreshCw size={15}/> Refresh</button></div>
          {pipelineRuns.length ? pipelineRuns.map(run=><article className="pipeline-run" key={run.run_id}><div className="pipeline-run-head"><b>{run.status.replaceAll("_"," ")}</b><small>{new Date(run.started_at).toLocaleString()} · {run.trigger}</small></div><div className="pipeline-run-metrics"><span>{run.indicators_enriched} enriched</span><span>{run.opportunities_found} opportunities</span><span>{run.candidates_created} candidates created</span><span>{run.candidates_skipped} skipped</span></div><div className="pipeline-stages">{Object.entries(run.stage_results||{}).map(([name,stage])=><span key={name} className={stage.status==="failed"?"stage-failed":stage.status==="partial"?"stage-partial":"stage-ok"}>{name.replaceAll("_"," ")}: {stage.status}</span>)}</div>{run.error_message&&<small className="muted">{run.error_message}</small>}</article>) : <p className="muted">No pipeline runs yet. Run the full pipeline to process available intelligence and prepare draft candidates.</p>}
        </section>
        <section className="panel feed-panel"><div className="panelhead"><div><b>Feed activity</b><p>Recent ingestion status</p></div></div>
          {feeds.length ? feeds.map(feed => <div className="feed-row" key={feed.name}><div><b>{feed.name}</b><small>{feed.last_run ? new Date(feed.last_run).toLocaleString() : "No run time"}</small></div><span className={feed.status === "succeeded" ? "feed-ok" : "feed-fail"}>{feed.status}</span><small>{feed.records_seen.toLocaleString()} records · {feed.indicators_created.toLocaleString()} new</small></div>) : <p className="muted">No feed runs recorded. Start with the CISA KEV sync.</p>}
        </section>
      </> : page === "ATT&CK catalog" ? <>
        <section className="banner catalog-banner"><ShieldCheck/><div><b>MITRE ATT&CK Enterprise · your detection coverage map</b><p>Use this catalogue to understand attacker behaviours, map them to tactics, and identify which techniques your detections should cover.</p></div><span>{attackTechniques.length} TECHNIQUES</span></section>
        <section className="stats catalog-stats">
          <article><div>Active techniques<ShieldCheck size={17}/></div><strong>{attackTechniques.filter(item=>!item.revoked&&!item.deprecated).length.toLocaleString()}</strong><small>Current behaviours in the catalog</small></article>
          <article><div>ATT&CK tactics<Network size={17}/></div><strong>{new Set(attackTechniques.flatMap(item=>item.tactics)).size}</strong><small>Adversary goals represented</small></article>
          <article><div>Sub-techniques<Layers3 size={17}/></div><strong>{attackTechniques.filter(item=>item.is_subtechnique&&!item.revoked&&!item.deprecated).length.toLocaleString()}</strong><small>Specific behaviour variants</small></article>
          <article><div>Platforms<Database size={17}/></div><strong>{new Set(attackTechniques.flatMap(item=>item.platforms)).size}</strong><small>Platforms represented in ATT&CK</small></article>
        </section>
        <section className="catalog-guide">
          <article><b>Why use this catalogue?</b><p>Translate threat activity into a shared language for threat hunting, detection engineering and coverage discussions.</p></article>
          <article><b>Tactic = attacker goal</b><p>The objective an adversary is trying to achieve, such as Initial Access, Execution or Exfiltration.</p></article>
          <article><b>Technique = how they do it</b><p>The behaviour or method used to achieve that goal. Use IDs to map detections consistently.</p></article>
        </section>
        <section className="panel intel-panel">
          <div className="panelhead"><div><b>Find a technique</b><p>Filter first, then scan concise technique summaries and platform coverage.</p></div><span>{visibleAttackTechniques.length} of {attackTechniques.length}</span></div>
          <div className="catalog-filters">
            <select value={attackTacticFilter} onChange={e=>{setAttackTacticFilter(e.target.value);setAttackTechniqueFilter("");}}><option value="">All tactics</option>{[...new Set(attackTechniques.flatMap(x=>x.tactics))].sort().map(t=><option key={t} value={t}>{t.replaceAll("_"," ")}</option>)}</select>
            <select value={attackTechniqueFilter} onChange={e=>setAttackTechniqueFilter(e.target.value)}><option value="">All techniques</option>{attackTechniques.filter(x=>!attackTacticFilter||x.tactics.includes(attackTacticFilter)).sort((a,b)=>a.external_id.localeCompare(b.external_id)).map(t=><option key={t.id} value={t.external_id}>{t.external_id} · {t.name}</option>)}</select>
            <div className="searchbar"><Search size={16}/><input value={attackSearch} onChange={e=>setAttackSearch(e.target.value)} placeholder="Search ID, technique or platform…"/></div>
            <button onClick={()=>{setAttackSearch("");setAttackTacticFilter("");setAttackTechniqueFilter("");}}>Clear filters</button>
          </div>
          <div className="technique-grid">{visibleAttackTechniques.map(item=><article className="technique-card" key={item.id}>
            <div className="technique-top"><b>{item.external_id}</b><span>{item.is_subtechnique?"SUB-TECHNIQUE":"TECHNIQUE"}</span></div>
            <h3>{item.name}</h3><p className="technique-summary">{item.description}</p>
            <div className="technique-tags">{item.tactics.map(t=><span className="tactic-tag" key={t}>{t.replaceAll("_"," ")}</span>)}</div>
            <div className="technique-platforms">{item.platforms.slice(0,4).map(p=><span key={p}>{p}</span>)}{item.platforms.length>4&&<span>+{item.platforms.length-4}</span>}</div>
            <div className="technique-footer"><span className={item.revoked?"tech-status revoked":item.deprecated?"tech-status deprecated":"tech-status active"}>{item.revoked?"Revoked":item.deprecated?"Deprecated":"Active"}</span><a href={item.source_url} target="_blank" rel="noreferrer">MITRE details ↗</a></div>
          </article>)}</div>
          {visibleAttackTechniques.length===0&&<p className="no-data">No techniques match these filters.</p>}
        </section>
      </> : page === "Threat graph" ? <>
        <section className="banner graph-banner"><Network/><div><b>Threat landscape at a glance</b><p>Explore source-backed entities and reported relationships. Explore source-backed entities, adversary behaviour and reported relationships with traceable evidence.</p></div><span>STIX 2.1</span></section>
        <section className="graph-overview">
          <div className="graph-overview-head"><div><label>INTELLIGENCE SNAPSHOT</label><b>What is connected right now</b></div><button onClick={()=>void loadThreatGraph()} disabled={loadingThreatGraph}><RefreshCw size={14} className={loadingThreatGraph?"spin":""}/>{loadingThreatGraph?"Refreshing…":"Refresh graph"}</button></div>
          <div className="graph-kpis">
            <article className="graph-kpi graph-kpi-blue"><span>ENTITIES</span><strong>{graphVisibleNodes.length}</strong><small>{graphTypeCounts.length} entity categories</small></article>
            <article className="graph-kpi graph-kpi-violet"><span>RELATIONSHIPS</span><strong>{graphVisibleEdges.length}</strong><small>Links between visible entities</small></article>
          </div>
          <div className="graph-overview-grid">
            <article className="graph-visual-panel">
              <div className="graph-section-title"><div><b>Entity landscape</b><small>Composition of the filtered graph</small></div><span>{graphVisibleNodes.length} total</span></div>
              {graphTypeCounts.length ? <div className="graph-type-list">{graphTypeCounts.map(([type,count])=><div className="graph-type-row" key={type}><span className={`graph-type-dot type-${type}`}/><span className="graph-type-name">{type.replaceAll("_"," ")}</span><div className="graph-type-track"><i style={{width:`${Math.max(4,(count/Math.max(1,graphVisibleNodes.length))*100)}%`}}/></div><b>{count}</b></div>)}</div> : <p className="no-data">No entities match these filters.</p>}
            </article>
            <article className="graph-visual-panel">
              <div className="graph-section-title"><div><b>Most connected entities</b><small>Ranked by visible relationship count</small></div><span>TOP 5</span></div>
              {graphConnectedCounts.length ? <div className="graph-leader-list">{graphConnectedCounts.map((node,index)=><button className={selectedGraphNodeId===node.id?"graph-leader active":"graph-leader"} key={node.id} onClick={()=>setSelectedGraphNodeId(node.id)}><span className={`graph-rank rank-${index+1}`}>{index+1}</span><span className="graph-leader-copy"><b>{node.name}</b><small>{node.entity_type.replaceAll("_"," ")}</small></span><strong>{node.connections}<small>links</small></strong></button>)}</div> : <p className="no-data">Relationship data will appear here when linked entities are available.</p>}
            </article>
          </div>
        </section>
        <section className="panel intel-panel graph-workspace">
          <div className="panelhead"><div><b>Explore the graph</b><p>Filter entities, select one, and inspect its connected evidence.</p></div><label className="upload-button graph-upload" aria-disabled="true" title="STIX import requires a backend"><input type="file" accept=".json,application/json" disabled onChange={e=>{void importStix(e.target.files?.[0]);e.currentTarget.value="";}}/>{"STIX import unavailable"}</label></div>
          <div className="searchbar"><Search size={16}/><input value={entitySearch} onChange={e=>setEntitySearch(e.target.value)} placeholder="Search entity, STIX ID or source…"/></div>
          <div className="graph-filterbar">
            <select value={entityTypeFilter} onChange={e=>setEntityTypeFilter(e.target.value)}><option value="">All entity types</option>{[...new Set(threatGraph.nodes.map(n=>n.entity_type))].sort().map(type=><option key={type} value={type}>{type.replaceAll("_"," ")}</option>)}</select>
            <select value={graphStatusFilter} onChange={e=>setGraphStatusFilter(e.target.value)}><option value="all">All statuses</option><option value="current">Current</option><option value="deprecated">Deprecated</option><option value="revoked">Revoked</option></select>
            <span className="graph-result-count">Showing {graphVisibleNodes.length} of {threatGraph.nodes.length}</span>
          </div>
          {threatGraph.truncated&&<p className="graph-truncated"><AlertTriangle size={14}/> Graph view is capped at 500 entities and 1,000 relationships. Refine your search to explore larger imports.</p>}
          <div className="graph-explorer-grid">
            <div className="graph-entity-list">
              {graphVisibleNodes.map(node=><article className={selectedGraphNodeId===node.id?"graph-entity-card selected":"graph-entity-card"} key={node.id}>
                <div className="graph-entity-top"><span className={`graph-entity-type type-${node.entity_type}`}>{node.entity_type.replaceAll("_"," ")}</span><span className={`graph-status status-${node.revoked?"revoked":node.deprecated?"deprecated":"current"}`}>{node.revoked?"Revoked":node.deprecated?"Deprecated":"Current"}</span></div>
                <b>{node.name}</b><small className="graph-entity-id">{node.external_id}</small>
                <div className="graph-entity-bottom"><button onClick={()=>setSelectedGraphNodeId(node.id)}>{selectedGraphNodeId===node.id?"Selected":"View links"} <ChevronRight size={13}/></button></div>
              </article>)}
              {!loadingThreatGraph&&graphVisibleNodes.length===0&&<p className="no-data">{threatGraph.nodes.length?"No entities match the selected filters.":"No threat entities yet. Import a STIX 2.1 bundle to build your graph."}</p>}
            </div>
            <aside className="graph-detail-panel">
              {selectedGraphNode ? <>
                <div className="graph-detail-head"><span className={`graph-entity-type type-${selectedGraphNode.entity_type}`}>{selectedGraphNode.entity_type.replaceAll("_"," ")}</span><span className={`graph-status status-${selectedGraphNode.revoked?"revoked":selectedGraphNode.deprecated?"deprecated":"current"}`}>{selectedGraphNode.revoked?"Revoked":selectedGraphNode.deprecated?"Deprecated":"Current"}</span></div>
                <h3>{selectedGraphNode.name}</h3><p className="graph-detail-id">{selectedGraphNode.external_id}</p>
                {selectedGraphNode.impact&&<div className="graph-impact-detail"><span>IMPACT / CONTEXT</span><p>{selectedGraphNode.impact}</p></div>}

                <p className="graph-detail-description">{selectedGraphNode.description||"No description was provided by the source."}</p>
                <div className="graph-detail-meta"><span>Source</span><b>{selectedGraphNode.source_name}</b><span>Reference</span><b>{selectedGraphNode.source_reference}</b></div>
                {selectedGraphNode.source_url&&<a className="graph-source-link" href={selectedGraphNode.source_url} target="_blank" rel="noreferrer">Open source reference ↗</a>}
                <div className="graph-connected-heading"><b>Connected relationships</b><span>{selectedGraphEdges.length}</span></div>
                {selectedGraphEdges.length?selectedGraphEdges.map(edge=><div className="graph-connection" key={edge.id}><div><b>{edge.source===selectedGraphNode.id?threatGraph.nodes.find(n=>n.id===edge.target)?.name||edge.target:threatGraph.nodes.find(n=>n.id===edge.source)?.name||edge.source}</b><span className="connection-direction">{edge.source===selectedGraphNode.id?"OUTGOING":"INCOMING"} · {edge.relationship_type.replaceAll("_"," ")}</span></div><span className={`graph-status status-${edge.assertion_status.includes("refuted")?"revoked":edge.assertion_status.includes("inferred")?"deprecated":"current"}`}>{edge.assertion_status.replaceAll("_"," ")}</span><small>{edge.source_name}</small>{edge.source_url&&<a href={edge.source_url} target="_blank" rel="noreferrer">Evidence source ↗</a>}</div>):<p className="no-data">No linked relationships for this entity in the current result set.</p>}
              </> : <div className="graph-detail-empty"><Network size={28}/><b>Select an entity to explore its connections</b><p>Choose an entity card or a top connected entity to see its relationships, direction and source evidence.</p></div>}
            </aside>
          </div>
          <div className="graph-legend"><span><i className="legend-dot legend-blue"/> Actor / campaign</span><span><i className="legend-dot legend-red"/> Malware / tool</span><span><i className="legend-dot legend-violet"/> Infrastructure / vulnerability</span><span><i className="legend-dot legend-green"/> Current / source-observed</span><span><i className="legend-dot legend-amber"/> Deprecated / inferred</span></div>
          {loadingThreatGraph&&<p className="muted">Loading threat graph…</p>}
          {threatGraph.nodes.length>0&&threatGraph.edges.length===0&&<p className="no-data">Entities are loaded, but no relationships with both endpoints are available yet.</p>}
        </section>
            </> : page === "Correlation" ? <>
        <section className="banner"><BrainCircuit/><div><b>Evidence-backed detection opportunities</b><p>Correlations are created only from exact ATT&CK technique IDs or CVE references shared by intelligence evidence and detection intents. No actor or campaign attribution is inferred.</p></div><span>EXPLAINABLE</span></section>
        <section className="panel intel-panel">
          <div className="panelhead"><div><b>Detection opportunities</b><p>Grouped by matching detection intent, with supporting indicators and source evidence counts.</p></div><button onClick={()=>void loadOpportunities()} disabled={loadingOpportunities}><RefreshCw size={15} className={loadingOpportunities?"spin":""}/> Refresh</button></div>
          {opportunities.map(item=><article className="candidate-card" key={item.intent_id}>
            <div className="candidate-title"><div><b>{item.title}</b><small>{item.severity.toUpperCase()} · {item.status.toUpperCase()} · {item.target_platforms.map(p=>p.toUpperCase()).join(", ")}</small></div><span>{item.indicator_count} indicators</span></div>
            <p className="muted">{item.rationale}</p>
            <div className="library-filters">{item.matched_techniques.map(id=><span className="type-pill" key={id}>ATT&amp;CK {id}</span>)}{item.matched_cves.map(id=><span className="type-pill" key={id}>{id}</span>)}</div>
            <div className="table-wrap"><table><thead><tr><th>INDICATOR</th><th>SEVERITY</th><th>CONFIDENCE</th><th>FRESHNESS</th><th>EVIDENCE</th></tr></thead><tbody>{item.indicators.map(ind=><tr key={ind.indicator_id}><td><b>{ind.value}</b><small>{ind.indicator_type.toUpperCase()}</small></td><td>{ind.severity}</td><td>{ind.confidence}%</td><td>{ind.freshness}</td><td>{ind.evidence_count}</td></tr>)}</tbody></table></div>
            <small className="muted">{item.evidence_count} total source evidence records · Association: explicit reference</small>
          </article>)}
          {!loadingOpportunities && opportunities.length===0&&<p className="no-data">No evidence-backed detection opportunities yet. Import or sync intelligence and create detection intents with matching ATT&amp;CK IDs or CVE evidence references.</p>}
        </section>
      </> : page === "Rule generator" ? <>
        <section className="banner"><Sparkles/><div><b>Generate queries for your SIEMs</b><p>Choose a detection use case and generate one query per selected language. The current generator supports four formats: Splunk SPL, Sentinel KQL, Google SecOps YARA-L and Sigma YAML.</p></div><span>4 FORMATS</span></section>
        <section className="panel" style={{marginTop:16,padding:15}}>
          <b>How to use it</b>
          <p className="muted" style={{marginTop:7}}>1. Describe the activity you want to detect. 2. Add the ATT&amp;CK technique IDs if known. 3. Choose the platforms. 4. Generate and copy the query you need.</p>
          <p className="muted" style={{marginTop:7}}>Available formats: Splunk SPL, Microsoft Sentinel KQL, Chronicle YARA-L 2.0 and Sigma YAML. Queries use your intent's telemetry fields. Confirm those fields match your own data source before deploying.</p>
        </section>
        <section className="columns">
          <article className="panel"><div className="panelhead"><div><b>Create detection intent</b><p>Define behavior and telemetry before generating queries.</p></div></div>
            <div className="intent-form">
              <label>DETECTION NAME</label><input value={intentTitle} onChange={e=>setIntentTitle(e.target.value)} placeholder="e.g. Suspicious PowerShell download"/>
              <label>DESCRIPTION</label><textarea value={intentDescription} onChange={e=>setIntentDescription(e.target.value)} placeholder="What activity should this detection identify?"/>
              <label>BEHAVIOR DETAILS</label><textarea value={intentBehavior} onChange={e=>setIntentBehavior(e.target.value)} placeholder="Describe the attacker behavior, sequence and expected signals."/>
              <small className="muted">Tip: mention known behaviors or tools (for example PowerShell, certutil or encoded commands) to make the free templates more specific.</small>
              <label>MITRE ATT&CK TECHNIQUE IDS (OPTIONAL)</label><input value={attackTechniqueIds} onChange={e=>setAttackTechniqueIds(e.target.value)} placeholder="T1059.001, T1105"/>
              <label>QUERY LANGUAGES</label><div className="platform-options">{["splunk","sentinel","chronicle","sigma"].map(platform=><label className={"platform-choice platform-"+platform} key={platform}><input type="checkbox" checked={targetPlatforms.includes(platform)} onChange={e=>setTargetPlatforms(old=>e.target.checked?[...old,platform]:old.filter(x=>x!==platform))}/><span>{platform==="sentinel"?"Microsoft Sentinel KQL":platform==="chronicle"?"Google SecOps YARA-L":platform==="sigma"?"Sigma YAML":"Splunk SPL"}</span></label>)}</div>
              <button className="primary-action" onClick={createIntent} disabled={creatingIntent}>{creatingIntent?"Saving intent…":"Save detection intent"}</button>
            </div>
          </article>
          <article className="panel"><div className="panelhead"><div><b>Generate candidates</b><p>Build drafts locally from free, deterministic platform templates.</p></div></div>
            <div className="intent-form">
              <label>SAVED DETECTION INTENT</label><select value={selectedIntentId} onChange={e=>{const id=e.target.value;setSelectedIntentId(id);const found=intents.find(x=>x.id===id);if(found)setTargetPlatforms(found.target_platforms);}}><option value="">Select a detection intent</option>{intents.map(item=><option key={item.id} value={item.id}>{item.title}</option>)}</select>
              <label>GENERATE QUERIES FOR</label><div className="platform-options">{["splunk","sentinel","chronicle","sigma"].map(platform=><label className={"platform-choice platform-"+platform} key={platform}><input type="checkbox" checked={targetPlatforms.includes(platform)} onChange={e=>setTargetPlatforms(old=>e.target.checked?[...old,platform]:old.filter(x=>x!==platform))}/><span>{platform==="sentinel"?"Sentinel KQL":platform==="chronicle"?"Chronicle YARA-L":platform==="sigma"?"Sigma YAML":"Splunk SPL"}</span></label>)}</div>
              <button className="primary-action" onClick={generateRules} disabled={generating || !selectedIntentId || targetPlatforms.length === 0}><Sparkles size={15}/>{generating?"Generating…":"Generate queries"}</button>
              <p className="muted">One click generates all selected languages. No review queue or approval workflow.</p>
            </div>
          </article>
        </section>
        <section className="panel intel-panel"><div className="panelhead"><div><b>Generated query formats</b><p>One latest query per language for the selected use case. Earlier versions remain in the Rule Library.</p></div><span>{latestGeneratedCandidates.length} formats</span></div>
          {latestGeneratedCandidates.length ? latestGeneratedCandidates.map(candidate=><article className={"candidate-card language-"+candidate.platform} key={candidate.id}>
            <div className="candidate-title"><div><b>{candidate.platform==="sentinel"?"Microsoft Sentinel KQL":candidate.platform==="chronicle"?"Google SecOps YARA-L 2.0":candidate.platform==="sigma"?"Sigma YAML":"Splunk SPL"}</b><small>{candidate.name} · Latest version v{candidate.version}</small></div><button className="copy-query" onClick={()=>navigator.clipboard?.writeText(candidate.query).then(()=>setNotice("Query copied to clipboard."))}>Copy query</button></div>
            <pre>{candidate.query}</pre>
          </article>) : <p className="no-data">No generated queries for this use case yet. Select one or more languages and generate.</p>}
        </section>
      </> : page === "Rule library" ? <>
        <section className="banner"><Database/><div><b>Detection rule library · one use case, versioned queries</b><p>Rules are grouped by detection use case and language. CVEs are grouped by NVD CWE weakness category. CWE describes vulnerability type; ATT&CK describes adversary behaviour, so IOC-only matches are not given artificial technique mappings.</p></div><span>VERSIONED</span></section>
        <section className="panel intel-panel">
          <div className="panelhead"><div><b>Rule library</b><p>Find a use case, then choose the language and version you need.</p></div><span>{libraryGroups.length} use cases · {filteredLibraryCandidates.length} versions</span></div>
          <div className="searchbar"><Search size={16}/><input value={libraryQuery} onChange={e=>{setLibraryQuery(e.target.value);setLibraryOffset(0);}} placeholder="Search rule names or query text…"/></div>
          <div className="library-filters">
            <select value={libraryTactic} onChange={e=>setLibraryTactic(e.target.value)}><option value="">All tactics</option>{[...new Set(attackTechniques.flatMap(x=>x.tactics))].sort().map(t=><option key={t} value={t}>{t.replaceAll("_"," ")}</option>)}</select>
            <select value={libraryTechnique} onChange={e=>setLibraryTechnique(e.target.value)}><option value="">All techniques</option>{[...new Set(intents.flatMap(x=>x.attack_techniques||[]))].sort().map(t=><option key={t} value={t}>{t}</option>)}</select>
            <select value={libraryPlatform} onChange={e=>{setLibraryPlatform(e.target.value);setLibraryOffset(0);}}><option value="">All platforms</option>{["splunk","sentinel","chronicle","sigma","crowdstrike"].map(p=><option key={p} value={p}>{p==="sigma"?"SIGMA YAML":p.toUpperCase()}</option>)}</select>
            
            <button onClick={()=>void loadRuleLibrary()}><RefreshCw size={15}/> Refresh</button>
          </div>
          {libraryGroups.map(group=><article className="library-usecase" key={group.key}>
            <div className="library-usecase-head"><div><b>{group.title}</b><small>{group.subtitle} · {group.candidates.length} language/version records</small></div><span>{group.key.startsWith("ioc::")?"IOC USE CASE":"USE CASE"}</span></div>
            {Object.values(group.candidates.reduce<Record<string, RuleCandidate[]>>((batches, candidate) => { (batches[candidate.intent_id] ||= []).push(candidate); return batches; }, {})).map(batchCandidates=>{
              const batchIntent=intents.find(x=>x.id===batchCandidates[0]?.intent_id);
              const batchTitle=batchIntent?.title||"Detection use case";
              const batchMatch=batchTitle.match(/^ThreatWeave Active IOC Coverage:\s*([a-z0-9_-]+):(\d+)$/i);
              const batchKey=batchCandidates[0]?.intent_id||group.key;
              return <section className="library-batch" key={batchKey}>
                {batchMatch&&<div className="library-batch-head"><b>Indicator set</b><span>{batchCandidates[0]?.generation_metadata?.indicator_count??"—"} active indicators{batchMatch[1].startsWith("cve-cwe-")?` · ${batchMatch[1].replace("cve-cwe-","CWE-")}`:""}</span></div>}
                <div className="library-platform-grid">{Object.entries(batchCandidates.reduce<Record<string, RuleCandidate[]>>((byPlatform, candidate) => { (byPlatform[candidate.platform] ||= []).push(candidate); return byPlatform; }, {})).map(([platform, versions])=>{
                  const ordered=[...versions].sort((a,b)=>b.version-a.version);
                  const selectionKey=group.key+"::"+batchKey+"::"+platform;
                  const selected=ordered.find(item=>item.version===libraryVersionSelection[selectionKey])||ordered[0];
                  const selectedIntent=intents.find(x=>x.id===selected.intent_id);
                  const mappedTechniques=(selectedIntent?.attack_techniques||[]).map(id=>({id,detail:attackTechniques.find(t=>t.external_id===id)}));
                  const isIoc=selected.generator==="ioc-intel";
                  const batchKind=(selectedIntent?.title||"").match(/^ThreatWeave Active IOC Coverage:\\s*([a-z0-9_-]+):/i)?.[1]?.toLowerCase()||"";
                  const contextualExploitTechnique=isIoc&&batchKind.startsWith("cve")?attackTechniques.find(t=>t.external_id==="T1190"):undefined;
                  const effectiveMappedTechniques=mappedTechniques.length?mappedTechniques:contextualExploitTechnique?[{id:"T1190",detail:contextualExploitTechnique}]:[];
                  const mappedTactics=[...new Set(effectiveMappedTechniques.flatMap(item=>item.detail?.tactics||[]))];
                  const platformName=platform==="sentinel"?"Microsoft Sentinel KQL":platform==="chronicle"?"Google SecOps YARA-L 2.0":platform==="sigma"?"Sigma YAML":platform==="crowdstrike"?"CrowdStrike":"Splunk SPL";
                  return <section className={"library-platform language-"+platform} key={platform}>
                    <div className="library-platform-head"><b>{platformName}</b><label>VERSION <select value={selected.version} onChange={e=>setLibraryVersionSelection(old=>({...old,[selectionKey]:Number(e.target.value)}))}>{ordered.map(version=><option key={version.id} value={version.version}>v{version.version}{version===ordered[0]?" · Latest":""}</option>)}</select></label></div>
                    <div className="library-platform-meta"><span>{isIoc?"Threat-intel maintained":selected.generator}</span><span>{selected.validation_status}</span></div>
                    <pre>{selected.query}</pre>
                    <button className="copy-query" onClick={()=>navigator.clipboard?.writeText(selected.query).then(()=>setNotice("Query copied to clipboard."))}>Copy {platformName} query</button>
                    <div className="rule-attack-context">
                      <div><b>MITRE tactics</b><p>{mappedTactics.length?mappedTactics.map(t=>t.replaceAll("_"," ")).join(" · "):isIoc?"Not directly applicable — IOC matching detects indicator presence, not an adversary tactic.":"Mapping required — no tactic is currently linked to this use case."}</p></div>
                      <div><b>MITRE techniques</b><p>{effectiveMappedTechniques.length?effectiveMappedTechniques.map(item=>`${item.id}${item.detail? ` · ${item.detail.name}`:""}`).join(" · "):isIoc?"Not inferable from an IOC match alone — add behaviour-specific mapping when telemetry supports it.":"Mapping required — add ATT&CK technique IDs to this use case to complete its mapping."}</p></div>
                    </div>
                  </section>;
                })}</div>
              </section>;
            })}
          </article>)}
          {filteredLibraryCandidates.length===0&&<p className="no-data">No rules match the selected filters.</p>}
          <div className="library-pagination"><button disabled={libraryOffset===0} onClick={()=>setLibraryOffset(x=>Math.max(0,x-100))}>Previous</button><span>Showing {libraryOffset+1}–{libraryOffset+candidates.length}</span><button disabled={candidates.length<100} onClick={()=>setLibraryOffset(x=>x+100)}>Next</button></div>
        </section>
      </> : page === "Effectiveness" ? <>
        <section className="banner"><Activity/><div><b>Detection quality and ATT&CK coverage</b><p>Transparent workflow-readiness indicators based on explicit mappings, validation, telemetry hints and offline test runs.</p></div><span>PRIORITIZATION</span></section>
        <div className="effectiveness-toolbar"><small>Historical database metrics are not refreshed in the static portfolio</small><button disabled title="Effectiveness metrics require live test-run data"><RefreshCw size={14} className={loadingEffectiveness?"spin":""}/> Refresh metrics</button></div>
        {effectiveness ? <>
          <section className="stats">
            {[
              {label:"ATT&CK techniques covered",value:`${effectiveness.summary.covered_techniques}/${effectiveness.summary.active_techniques}`,note:`${effectiveness.summary.coverage_percent}% explicit coverage`},
              {label:"Coverage gaps",value:effectiveness.summary.coverage_gaps,note:"Active techniques without a mapped intent"},
              {label:"Detection intents",value:effectiveness.summary.detection_intents,note:`${effectiveness.summary.intents_with_candidates} with candidates`},
              {label:"Average readiness",value:`${effectiveness.summary.average_readiness}%`,note:"Equal-weight workflow readiness score"},
            ].map(item=><article key={item.label}><div>{item.label}<Activity size={17}/></div><strong>{item.value}</strong><small>{item.note}</small></article>)}
          </section>
          <section className="panel intel-panel"><div className="panelhead"><div><b>ATT&CK tactic coverage</b><p>Exact technique ID mappings from detection intents, not inferred query behavior.</p></div><span>{effectiveness.tactics.length} tactics</span></div>
            {effectiveness.tactics.length?effectiveness.tactics.map((t:any)=><div className="coverage-row" key={t.tactic}><div><b>{t.tactic.replaceAll("_"," ")}</b><small>{t.covered_count}/{t.technique_count} techniques</small></div><div className="coverage-track"><span style={{width:`${t.coverage_percent}%`}}/></div><strong>{t.coverage_percent}%</strong></div>):<p className="no-data">No ATT&CK techniques loaded yet. Sync the ATT&CK catalog to populate coverage.</p>}
          </section>
          <section className="panel intel-panel"><div className="panelhead"><div><b>Detection readiness</b><p>Per-intent score with its underlying dimensions.</p></div><span>{effectiveness.detections.length} intents</span></div>
            {effectiveness.detections.length?effectiveness.detections.map((d:any)=><article className="readiness-card" key={d.intent_id}><div className="readiness-head"><div><b>{d.title}</b><small>{d.severity.toUpperCase()} · {d.technique_ids.length?d.technique_ids.join(", "):"No explicit ATT&CK mapping"}</small></div><strong>{d.readiness_score}%</strong></div><div className="coverage-track"><span style={{width:`${d.readiness_score}%`}}/></div><div className="readiness-dimensions">{d.dimensions.map((x:any)=><span key={x.name}>{x.name}: <b>{x.status==="not_assessed"||x.status==="not_tested"?"Not assessed":x.score+"%"}</b></span>)}</div><div className="platform-readiness">{d.platforms.map((p:any)=><span key={p.candidate_id}>{p.platform} · v{p.version} · validation {p.validation_status} · tests {p.test_status}</span>)}</div></article>):<p className="no-data">Create detection intents and candidates to calculate readiness.</p>}
          </section>
          <section className="panel intel-panel"><div className="panelhead"><div><b>Uncovered ATT&CK techniques</b><p>Prioritization candidates; not claims that every technique should have a detection.</p></div><span>{effectiveness.summary.coverage_gaps} gaps</span></div><div className="table-wrap"><table><thead><tr><th>TECHNIQUE</th><th>TACTICS</th><th>PLATFORMS</th></tr></thead><tbody>{effectiveness.techniques.filter((t:any)=>!t.covered).slice(0,100).map((t:any)=><tr key={t.technique_id}><td><b>{t.technique_id} · {t.name}</b></td><td>{t.tactics.join(", ")||"—"}</td><td>{t.platforms.join(", ")||"—"}</td></tr>)}</tbody></table></div></section>
          <section className="panel intel-panel"><div className="panelhead"><div><b>Scoring methodology</b><p>Read before interpreting the dashboard.</p></div></div><p className="methodology">{effectiveness.methodology.readiness_score}</p><p className="methodology">{effectiveness.methodology.attck_coverage}</p><ul className="limitations">{effectiveness.methodology.limitations.map((item:string)=><li key={item}>{item}</li>)}</ul></section>
        </>:<div className="panel no-data">{loadingEffectiveness?"Loading effectiveness metrics…":"No metrics available."}</div>}
      </> : page === "Validation" || page === "Review queue" ? <>
        <section className="banner"><ShieldCheck/><div><b>{page}</b><p>This section is no longer part of the simplified workspace.</p></div><span>HIDDEN</span></section>
        <section className="panel intel-panel"><div className="panelhead"><div><b>Candidate inventory</b><p>Select an intent to inspect its candidates.</p></div><span>{candidates.length} candidates</span></div>
          <div className="field"><label>Offline test suite (JSON)</label><textarea rows={8} value={testSuiteJson} onChange={e=>setTestSuiteJson(e.target.value)} spellCheck={false}/><small className="muted">Assertions inspect query text only. Fixtures are context; they are not executed as events.</small></div>
          <select className="intent-select" value={selectedIntentId} onChange={e=>setSelectedIntentId(e.target.value)}><option value="">Select intent</option>{intents.map(item=><option key={item.id} value={item.id}>{item.title}</option>)}</select>
          {candidates.map(candidate=><article className="candidate-card" key={candidate.id}><div className="candidate-title"><div><b>{candidate.name}</b><small>{candidate.platform.toUpperCase()} · V{candidate.version}</small></div><span>{candidate.validation_status}</span></div><pre>{candidate.query}</pre><button disabled title="Test execution requires a backend">{runningTests[candidate.id]?"Running offline checks…":"Run offline checks"}</button>{testRuns[candidate.id]&&<div className="test-report"><b>{testRuns[candidate.id].status.toUpperCase()} · {testRuns[candidate.id].passed_cases}/{testRuns[candidate.id].total_cases} cases passed</b><small>Regression: {testRuns[candidate.id].regression_report.status}</small>{testRuns[candidate.id].case_results.map(result=><small key={result.name}>{result.status==="passed"?"✓":"✕"} {result.name} · {result.scenario_type}</small>)}{testRuns[candidate.id].regression_report.regressions.map(name=><small key={name}>Regression: {name}</small>)}</div>}<small className="muted">Not approved · Not deployable</small></article>)}
        </section>
      </> : <>
        <section className="banner"><Activity/><div><b>Your workspace is ready for detection engineering</b><p>Start by ingesting trusted intelligence. Rule generation and approval workflows will build on this foundation.</p></div><span>PHASE 2</span></section>
        <section className="stats">{stats.map(({label,value,note,icon:Icon})=><article key={label}><div>{label}<Icon size={18}/></div><strong>{loading ? "…" : value.toLocaleString?.() ?? value}</strong><small>{note}</small></article>)}</section>
        <section className="columns"><article className="panel"><div className="panelhead"><div><b>Core workflow</b><p>Build the intelligence-to-detection pipeline.</p></div></div>
          {[{title:"Ingest threat intelligence",desc:"CISA KEV connector is available in Threat Intelligence.",icon:Radar},{title:"Enrich and correlate",desc:"Normalize evidence and map relationships and ATT&CK techniques.",icon:Database},{title:"Generate SIEM queries",desc:"Create copy-ready queries in Splunk, Sentinel and Chronicle formats.",icon:Sparkles}].map(({title,desc,icon:Icon})=><div className="step" key={title}><Icon/><div><b>{title}</b><small>{desc}</small></div><label>ROADMAP</label><ChevronRight size={15}/></div>)}
        </article><article className="panel activity"><div className="panelhead"><div><b>Latest intelligence run</b><p>Most recent feed execution</p></div><ArrowUpRight/></div><div className="empty"><CheckCircle2/><b>{summary?.latest_run ? summary.latest_run.status : "Waiting for first sync"}</b><p>{summary?.latest_run ? `${summary.latest_run.records_seen} records checked from ${summary.latest_run.source}.` : "Open Threat Intelligence and run the CISA KEV connector to start."}</p><button onClick={() => setPage("Threat intelligence")}>Open Intelligence Center</button></div></article></section>
      </>}
      <div className="footnote"><AlertTriangle size={15}/> Intelligence feed content is treated as untrusted evidence. Generated detections remain candidates until validated and approved; production deployment is disabled.</div>
      <footer>THREATWEAVE　•　THREAT INTELLIGENCE &amp; DETECTION ENGINEERING</footer>
    </main>
  </div>;
}
export default App;