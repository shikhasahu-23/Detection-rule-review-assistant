import { useEffect, useState } from "react";
import { Activity, AlertTriangle, ArrowUpRight, Bot, BrainCircuit, CheckCircle2, ChevronRight, Database, FileSearch, Layers3, LockKeyhole, Radar, ShieldCheck, ShieldEllipsis, Sparkles } from "lucide-react";

const nav = [
  { label: "Overview", icon: Layers3, active: true, locked: false },
  { label: "Threat intelligence", icon: Radar, locked: true },
  { label: "Rule generator", icon: Sparkles, locked: true },
  { label: "Validation", icon: ShieldCheck, locked: true },
  { label: "Review queue", icon: FileSearch, locked: true },
  { label: "Rule library", icon: Database, locked: true },
];
const stats = [
  { label: "Active intelligence", value: "—", note: "Feed setup pending", icon: Radar },
  { label: "Candidate detections", value: "—", note: "Generation not enabled", icon: BrainCircuit },
  { label: "Pending reviews", value: "—", note: "Review workflow not enabled", icon: FileSearch },
  { label: "Approved rules", value: "—", note: "No authenticated rule library", icon: ShieldCheck },
];

type ApiState = "checking" | "ready" | "unavailable" | "not-configured";

function ApiConnection() {
  const [state, setState] = useState<ApiState>("checking");
  useEffect(() => {
    const apiBaseUrl = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "");
    if (!apiBaseUrl) {
      setState("not-configured");
      return;
    }
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 10000);
    fetch(`${apiBaseUrl}/ready`, { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error("API readiness check failed");
        return response.json();
      })
      .then((result: { status?: string }) => setState(result.status === "ready" ? "ready" : "unavailable"))
      .catch(() => setState("unavailable"))
      .finally(() => window.clearTimeout(timeout));
    return () => {
      controller.abort();
      window.clearTimeout(timeout);
    };
  }, []);

  const labels: Record<ApiState, string> = {
    checking: "Checking API…",
    ready: "API + database ready",
    unavailable: "API unavailable",
    "not-configured": "API URL not configured",
  };
  return <span className={`api-connection api-${state}`} role="status"><span className="api-dot" />{labels[state]}</span>;
}

export default function App() {
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><div className="brandmark"><ShieldEllipsis /></div><div><b>Threat Detection Hub</b><small>DETECTION ENGINEERING</small></div></div>
        <label>WORKSPACE</label>
        <div className="workspace"><span>S</span><div><b>Security Engineering</b><small>Team workspace</small></div><ChevronRight size={15} /></div>
        <nav aria-label="Workspace navigation">
          {nav.map(({ label, icon: Icon, active, locked }) => (
            <a className={active ? "nav active" : locked ? "nav nav-locked" : "nav"} href={active ? "#overview" : "#"} aria-disabled={locked} key={label}>
              <Icon size={17} />{label}{locked && <LockKeyhole className="nav-lock" size={13} />}
            </a>
          ))}
        </nav>
        <div className="sidebottom"><span className="live-dot" /> Foundation services initialized<hr /><div className="user"><b>SE</b><div>Workspace member<small>Authentication pending</small></div></div></div>
      </aside>
      <main id="overview">
        <header><span>Workspace　›　<b>Overview</b></span><div className="header-status"><ApiConnection /><small><span className="live-dot" /> DEVELOPMENT</small></div></header>
        <section className="heading">
          <div><label>DETECTION ENGINEERING WORKSPACE</label><h1>Welcome to Threat Detection Hub</h1><p>A foundation for threat intelligence, detection engineering and controlled rule review.</p></div>
          <button disabled title="Available after authentication and workflow setup"><Sparkles size={16} /> Generate detection <small>LOCKED</small></button>
        </section>
        <section className="banner"><Activity /><div><b>Foundation services are online</b><p>The API and database can be reached. Application workflows are not enabled yet.</p></div><span>PHASE 0</span></section>
        <section className="auth-notice" role="status">
          <div className="auth-icon"><LockKeyhole size={18} /></div>
          <div><b>Authentication setup is deferred</b><p>Sign-in provider selection is intentionally postponed. Protected intelligence, identity and rule operations remain unavailable until trusted authentication and organization/role mapping are configured. This keeps private workspace data behind the existing authorization checks.</p></div>
          <span>ACCESS LOCKED</span>
        </section>
        <section className="stats">{stats.map(({ label, value, note, icon: Icon }) => <article key={label}><div>{label}<Icon size={18} /></div><strong>{value}</strong><small>{note}</small></article>)}</section>
        <section className="columns">
          <article className="panel">
            <div className="panelhead"><div><b>Next implementation steps</b><p>Safe work that can continue before sign-in is selected.</p></div><small>0 of 3</small></div>
            <div className="progress" />
            {[
              { title: "Configure intelligence sources", desc: "Review feed connectors and prepare source configuration", icon: Radar },
              { title: "Define telemetry requirements", desc: "Document SIEM event sources and field mappings", icon: Database },
              { title: "Choose an authentication provider", desc: "Deferred — protected workflows stay locked until decided", icon: LockKeyhole },
            ].map(({ title, desc, icon: Icon }) => <div className="step" key={title}><Icon /><div><b>{title}</b><small>{desc}</small></div><label>NOT STARTED</label><ChevronRight size={15} /></div>)}
          </article>
          <article className="panel activity"><div className="panelhead"><div><b>Platform activity</b><p>Latest system events</p></div><ArrowUpRight /></div><div className="empty"><CheckCircle2 /><b>No application activity yet</b><p>Events will appear when authenticated workflows and integrations are configured.</p></div></article>
        </section>
        <div className="footnote"><AlertTriangle size={15} /> API readiness confirms service and database connectivity only. It does not mean a user is authenticated or that application workflows are enabled.</div>
        <footer>THREAT DETECTION HUB　•　FOUNDATION BUILD　•　AUTHENTICATION DEFERRED</footer>
      </main>
    </div>
  );
}
