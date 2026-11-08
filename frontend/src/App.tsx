import { FormEvent, useEffect, useMemo, useState } from "react";
import { ShannonPanel } from "./ShannonPanel";
import { DetectionsPanel } from "./DetectionsPanel";
import { ThreatIntelPanel } from "./ThreatIntelPanel";
import { NucleiHealth, NucleiTarget, NucleiScan, getNucleiHealth, getNucleiTargets, getNucleiScans, registerNucleiTarget, startNucleiScan } from "./api";
import {
  ApiError, Asset, Finding, Incident, User, WazuhCollection, WazuhHealth, CrowdSecCollection, CrowdSecHealth, collectCrowdSec, getCrowdSecHealth,
  clearAccessToken, collectWazuh, getAccessToken, getAssets, getCurrentUser,
  getFindings, getIncidents, getWazuhHealth, login as loginRequest, saveAccessToken, updateFindingStatus, updateIncident,
} from "./api";

type View = "overview" | "assets" | "findings" | "detections" | "incidents" | "integrations" | "threat-intel";
type LoadState = "idle" | "loading" | "ready" | "error";

const navigation: { id: View; label: string; short: string }[] = [
  { id: "overview", label: "Overview", short: "OV" },
  { id: "assets", label: "Assets", short: "AS" },
  { id: "findings", label: "Findings", short: "FI" },
  { id: "detections", label: "Detections", short: "DE" },
  { id: "incidents", label: "Incidents", short: "IN" },
  { id: "integrations", label: "Integrations", short: "IG" },
  { id: "threat-intel", label: "Threat Intel", short: "TI" },
];

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}
function titleCase(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}
function severityClass(value: string): string {
  return "severity severity-" + value;
}
function ErrorMessage({ children }: { children: string }) {
  return <div className="inline-error" role="alert">{children}</div>;
}
function EmptyState({ title, detail }: { title: string; detail: string }) {
  return <div className="empty-state"><span className="empty-mark">—</span><strong>{title}</strong><p>{detail}</p></div>;
}

function LoginScreen({ onLogin }: { onLogin: (email: string, password: string) => Promise<void> }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      await onLogin(email.trim(), password);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Sign-in failed. Please try again.");
    } finally {
      setBusy(false);
    }
  }
  return <main className="login-screen">
    <div className="login-orbit orbit-one" /><div className="login-orbit orbit-two" />
    <section className="login-panel">
      <div className="brand brand-login"><span className="brand-mark">OA</span><span><strong>OpsAegis</strong><small>SECURITY OPERATIONS</small></span></div>
      <p className="eyebrow">IDENTITY VERIFICATION</p>
      <h1>Welcome back.</h1>
      <p className="login-copy">Sign in with your OpsAegis account to access your operational workspace.</p>
      <form onSubmit={submit} className="login-form">
        <label htmlFor="email">Email address</label>
        <input id="email" type="email" autoComplete="username" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="analyst@organization.com" required maxLength={320} />
        <label htmlFor="password">Password</label>
        <input id="password" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Enter your password" required maxLength={256} />
        {error && <ErrorMessage>{error}</ErrorMessage>}
        <button className="primary-button login-button" type="submit" disabled={busy}>{busy ? "Authenticating…" : "Sign in"} <span aria-hidden="true">→</span></button>
      </form>
      <p className="login-footnote">Protected by OpsAegis API authentication · Session-scoped access</p>
    </section>
  </main>;
}

function StatCard({ label, value, detail, accent }: { label: string; value: number; detail: string; accent: string }) {
  return <article className="stat-card">
    <div className="stat-heading"><span>{label}</span><i className={"stat-accent " + accent} /></div>
    <strong className="stat-value">{value.toLocaleString()}</strong>
    <span className="stat-detail">{detail}</span>
  </article>;
}

function DataTable({ view, assets, findings, incidents, query, user, canOperate, onFindingStatus, onIncidentUpdate }: {
  view: View; assets: Asset[]; findings: Finding[]; incidents: Incident[]; query: string;
  user: User; canOperate: boolean;
  onFindingStatus: (id: number, status: Finding["status"]) => void;
  onIncidentUpdate: (id: number, status: Incident["status"], resolution: string, assignToMe?: boolean) => void;
}) {
  const [resolutionNotes, setResolutionNotes] = useState<Record<number, string>>({});
  const [incidentStatuses, setIncidentStatuses] = useState<Record<number, Incident["status"]>>({});
  const needle = query.trim().toLowerCase();
  if (view === "assets") {
    const rows = assets.filter((item) => [item.name, item.asset_type, item.environment].join(" ").toLowerCase().includes(needle));
    if (!rows.length) return <EmptyState title={needle ? "No matching assets" : "No assets registered"} detail={needle ? "Try another search term." : "Assets will appear here when they are added through the OpsAegis API."} />;
    return <div className="table-wrap"><table><thead><tr><th>Asset</th><th>Type</th><th>IP address</th><th>Agent source</th><th>Environment</th><th>Last observed</th></tr></thead><tbody>{rows.map((item) => <tr key={item.id}><td><strong>{item.name}</strong><small>ASSET-{item.id}</small></td><td>{titleCase(item.asset_type)}</td><td>{item.ip_address ?? "—"}</td><td>{item.source_engine ? titleCase(item.source_engine) + (item.external_id ? " · " + item.external_id : "") : "Manual"}</td><td><span className="tag">{titleCase(item.environment)}</span></td><td>{item.last_seen_at ? formatDate(item.last_seen_at) : "—"}</td></tr>)}</tbody></table></div>;
  }
  if (view === "findings") {
    const rows = findings.filter((item) => [item.title, item.source_engine, item.status, item.severity].join(" ").toLowerCase().includes(needle));
    if (!rows.length) return <EmptyState title={needle ? "No matching findings" : "No findings recorded"} detail={needle ? "Try another search term." : "Findings appear after a security engine sends verified events or an authorized analyst records one."} />;
    return <div className="table-wrap"><table><thead><tr><th>Finding</th><th>Source</th><th>Severity</th><th>Status</th><th>Last seen</th></tr></thead><tbody>{rows.map((item) => <tr key={item.id}><td><strong>{item.title}</strong><small>FINDING-{item.id}{item.asset_id ? " · ASSET-" + item.asset_id : ""}</small></td><td>{titleCase(item.source_engine)}</td><td><span className={severityClass(item.severity)}>{titleCase(item.severity)}</span></td><td>{canOperate ? <select aria-label={"Update finding " + item.id + " status"} value={item.status} onChange={(event) => onFindingStatus(item.id, event.target.value as Finding["status"])}>{["new","triaged","accepted","false_positive","resolved"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}</select> : <span className="tag">{titleCase(item.status)}</span>}</td><td>{formatDate(item.last_seen_at)}</td></tr>)}</tbody></table></div>;
  }
  const rows = incidents.filter((item) => [item.title, item.status, item.severity].join(" ").toLowerCase().includes(needle));
  if (!rows.length) return <EmptyState title={needle ? "No matching incidents" : "No incidents recorded"} detail={needle ? "Try another search term." : "Incidents created in OpsAegis will appear here. No incidents are generated automatically yet."} />;
  return <div className="table-wrap"><table><thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Created</th></tr></thead><tbody>{rows.map((item) => <tr key={item.id}><td><strong>{item.title}</strong><small>INCIDENT-{item.id}</small></td><td><span className={severityClass(item.severity)}>{titleCase(item.severity)}</span></td><td>{canOperate ? <div className="incident-actions"><select aria-label={"Update incident " + item.id + " status"} value={incidentStatuses[item.id] ?? item.status} onChange={(event) => setIncidentStatuses((current) => ({...current,[item.id]:event.target.value as Incident["status"]}))}>{["open","investigating","contained","resolved","closed"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}</select><input aria-label={"Resolution note for incident " + item.id} value={resolutionNotes[item.id] ?? item.resolution ?? ""} onChange={(event) => setResolutionNotes((current) => ({...current,[item.id]:event.target.value}))} placeholder="Resolution note required to resolve/close" maxLength={10000}/><button className="secondary-button" onClick={() => onIncidentUpdate(item.id, incidentStatuses[item.id] ?? item.status, resolutionNotes[item.id] ?? item.resolution ?? "")}>Save response</button><button className="text-button" title={"Assign incident to " + user.email} onClick={() => onIncidentUpdate(item.id, incidentStatuses[item.id] ?? item.status, resolutionNotes[item.id] ?? item.resolution ?? "", true)}>Assign to me</button></div> : <span className="tag">{titleCase(item.status)}</span>}</td><td>{formatDate(item.created_at)}</td></tr>)}</tbody></table></div>;
}

function App() {
  const [token, setToken] = useState<string | null>(() => getAccessToken());
  const [user, setUser] = useState<User | null>(null);
  const [authState, setAuthState] = useState<LoadState>("idle");
  const [view, setView] = useState<View>("overview");
  const [assets, setAssets] = useState<Asset[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [wazuh, setWazuh] = useState<WazuhHealth | null>(null);
  const [crowdsec, setCrowdsec] = useState<CrowdSecHealth | null>(null);
  const [loadState, setLoadState] = useState<LoadState>("idle");
  const [loadErrors, setLoadErrors] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);
  const [collecting, setCollecting] = useState(false);
  const [collectingCrowdSec, setCollectingCrowdSec] = useState(false);
  const [collectionMessage, setCollectionMessage] = useState("");
  const [collectionError, setCollectionError] = useState("");

  const canOperate = user?.role === "admin" || user?.role === "analyst";

  useEffect(() => {
    if (!token) {
      setUser(null);
      setAuthState("idle");
      return;
    }
    let active = true;
    setAuthState("loading");
    getCurrentUser().then((account) => {
      if (active) {
        setUser(account);
        setAuthState("ready");
      }
    }).catch((reason: unknown) => {
      if (!active) return;
      clearAccessToken();
      setToken(null);
      setUser(null);
      setAuthState("idle");
      if (reason instanceof ApiError && reason.status !== 401) setLoadErrors([reason.message]);
    });
    return () => { active = false; };
  }, [token]);

  useEffect(() => {
    if (!user) return;
    let active = true;
    setLoadState("loading");
    setLoadErrors([]);
    const requests: Promise<unknown>[] = [
      getAssets(), getFindings(), getIncidents(),
      canOperate ? getWazuhHealth() : Promise.resolve(null),
      canOperate ? getCrowdSecHealth() : Promise.resolve(null),
    ];
    Promise.allSettled(requests).then((results) => {
      if (!active) return;
      const errors: string[] = [];
      const [assetResult, findingResult, incidentResult, wazuhResult, crowdsecResult] = results;
      if (assetResult.status === "fulfilled") setAssets(assetResult.value as Asset[]);
      else errors.push("Assets: " + (assetResult.reason instanceof Error ? assetResult.reason.message : "Unable to load assets."));
      if (findingResult.status === "fulfilled") setFindings(findingResult.value as Finding[]);
      else errors.push("Findings: " + (findingResult.reason instanceof Error ? findingResult.reason.message : "Unable to load findings."));
      if (incidentResult.status === "fulfilled") setIncidents(incidentResult.value as Incident[]);
      else errors.push("Incidents: " + (incidentResult.reason instanceof Error ? incidentResult.reason.message : "Unable to load incidents."));
      if (wazuhResult.status === "fulfilled") setWazuh(wazuhResult.value as WazuhHealth | null);
      else errors.push("Wazuh status: " + (wazuhResult.reason instanceof Error ? wazuhResult.reason.message : "Unable to load integration status."));
      if (results.some((result) => result.status === "rejected" && result.reason instanceof ApiError && result.reason.status === 401)) {
        clearAccessToken();
        setToken(null);
        setUser(null);
      }
      setLoadErrors(errors);
      setLoadState(errors.length ? "error" : "ready");
    });
    return () => { active = false; };
  }, [user, refreshKey, canOperate]);

  async function handleLogin(email: string, password: string) {
    const result = await loginRequest(email, password);
    saveAccessToken(result.access_token);
    setToken(result.access_token);
    setView("overview");
    setQuery("");
    setLoadErrors([]);
  }
  function handleLogout() {
    clearAccessToken();
    setToken(null);
    setUser(null);
    setAssets([]);
    setFindings([]);
    setIncidents([]);
    setWazuh(null);
    setView("overview");
  }
  async function handleCollect() {
    setCollecting(true);
    setCollectionError("");
    setCollectionMessage("");
    try {
      const result: WazuhCollection = await collectWazuh();
      setCollectionMessage("Collection completed: " + result.received + " received, " + result.inserted + " inserted, " + result.updated + " updated.");
      setRefreshKey((value) => value + 1);
    } catch (reason) {
      setCollectionError(reason instanceof Error ? reason.message : "Wazuh collection failed.");
    } finally {
      setCollecting(false);
    }
  }

  async function handleCollectCrowdSec() {
    setCollectingCrowdSec(true);
    setCollectionError("");
    setCollectionMessage("");
    try {
      const result: CrowdSecCollection = await collectCrowdSec();
      setCollectionMessage("CrowdSec active-decision sync completed: " + result.received + " received, " + result.inserted + " inserted, " + result.updated + " updated.");
      setRefreshKey((value) => value + 1);
    } catch (reason) {
      setCollectionError(reason instanceof Error ? reason.message : "CrowdSec collection failed.");
    } finally {
      setCollectingCrowdSec(false);
    }
  }

  const pageTitle = navigation.find((item) => item.id === view)?.label || "Overview";
  const filteredFindingCount = useMemo(() => findings.filter((item) => item.status === "new").length, [findings]);

  if (authState === "loading" || (token && !user && authState !== "idle")) {
    return <main className="auth-loading"><div className="loading-mark">OA</div><span>Verifying your session…</span></main>;
  }
  if (!token || !user) return <LoginScreen onLogin={handleLogin} />;

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand sidebar-brand"><span className="brand-mark">OA</span><span><strong>OpsAegis</strong><small>SECURITY OPERATIONS</small></span></div>
      <div className="workspace-label">WORKSPACE</div>
      <nav className="side-nav" aria-label="Main navigation">
        {navigation.map((item) => <button key={item.id} className={view === item.id ? "nav-item active" : "nav-item"} onClick={() => { setView(item.id); setQuery(""); }}><span className="nav-short">{item.short}</span><span>{item.label}</span>{item.id === "findings" && filteredFindingCount > 0 && <span className="nav-count">{filteredFindingCount}</span>}</button>)}
      </nav>
      <div className="sidebar-bottom">
        <div className="connection-indicator"><span className="live-dot" /><span>API session active</span></div>
        <div className="user-card"><div className="avatar">{user.email.slice(0, 1).toUpperCase()}</div><div className="user-meta"><strong>{user.email}</strong><small>{titleCase(user.role)}</small></div><button className="logout-button" onClick={handleLogout} aria-label="Sign out" title="Sign out">↗</button></div>
      </div>
    </aside>

    <main className="main-area">
      <header className="main-header">
        <div><p className="breadcrumb">OPSAEGIS <span>/</span> {pageTitle.toUpperCase()}</p><h1>{pageTitle}</h1></div>
        <div className="header-actions"><span className="role-chip">{titleCase(user.role)}</span><button className="secondary-button" onClick={() => setRefreshKey((value) => value + 1)} disabled={loadState === "loading"}><span aria-hidden="true">↻</span> Refresh</button></div>
      </header>

      {loadState === "loading" && <div className="loading-banner"><span className="spinner" /> Syncing records from OpsAegis API…</div>}
      {loadErrors.length > 0 && <div className="error-banner" role="alert"><strong>Some data could not be loaded.</strong>{loadErrors.map((error) => <span key={error}>{error}</span>)}</div>}
      {collectionMessage && <div className="success-banner" role="status">{collectionMessage}</div>}
      {collectionError && <div className="error-banner" role="alert">{collectionError}</div>}

      {view === "overview" && <div className="page-content">
        <section className="welcome-row"><div><p className="eyebrow">OPERATIONAL SNAPSHOT</p><h2>Security posture at a glance.</h2><p>Live records retrieved from your OpsAegis database. No demo metrics or synthetic telemetry are included.</p></div><div className="snapshot-stamp"><span className="live-dot" /> API DATA SESSION <small>{loadState === "ready" ? "LATEST API READ COMPLETE" : loadState === "error" ? "API READ DEGRADED" : "SYNCING API DATA"}</small></div></section>
        <section className="stats-grid">
          <StatCard label="REGISTERED ASSETS" value={assets.length} detail="Records returned · max 200" accent="blue" />
          <StatCard label="TOTAL FINDINGS" value={findings.length} detail="Records returned · max 200" accent="amber" />
          <StatCard label="NEW FINDINGS" value={filteredFindingCount} detail="Awaiting analyst triage" accent="red" />
          <StatCard label="OPEN INCIDENTS" value={incidents.filter((item) => item.status.toLowerCase() === "open").length} detail="Current open status" accent="violet" />
        </section>
        <section className="overview-grid">
          <article className="panel"><div className="panel-heading"><div><p className="eyebrow">LATEST ACTIVITY</p><h3>Recent findings</h3></div><button className="text-button" onClick={() => setView("findings")}>View all <span>→</span></button></div>
            {findings.length ? <div className="activity-list">{findings.slice(0, 5).map((item) => <div className="activity-row" key={item.id}><span className={"activity-icon " + item.severity}>{item.severity === "critical" || item.severity === "high" ? "!" : "•"}</span><div className="activity-copy"><strong>{item.title}</strong><small>{titleCase(item.source_engine)} · {formatDate(item.last_seen_at)}</small></div><span className={severityClass(item.severity)}>{titleCase(item.severity)}</span></div>)}</div> : <EmptyState title="No findings yet" detail="Verified findings will be listed here." />}
          </article>
          <article className="panel"><div className="panel-heading"><div><p className="eyebrow">RESPONSE WORKFLOW</p><h3>Recent incidents</h3></div><button className="text-button" onClick={() => setView("incidents")}>View all <span>→</span></button></div>
            {incidents.length ? <div className="activity-list">{incidents.slice(0, 5).map((item) => <div className="activity-row" key={item.id}><span className="incident-icon">↗</span><div className="activity-copy"><strong>{item.title}</strong><small>{titleCase(item.status)} · {formatDate(item.created_at)}</small></div><span className={severityClass(item.severity)}>{titleCase(item.severity)}</span></div>)}</div> : <EmptyState title="No incidents yet" detail="Incidents recorded by your team will appear here." />}
          </article>
        </section>
        <section className="panel engine-panel"><div className="panel-heading"><div><p className="eyebrow">INTEGRATION LAYER</p><h3>Security engines</h3></div><button className="text-button" onClick={() => setView("integrations")}>Integration details <span>→</span></button></div><EngineCards wazuh={wazuh} crowdsec={crowdsec} /></section>
      </div>}

      {view !== "overview" && <div className="page-content">
        {view !== "detections" && view !== "threat-intel" && <section className="list-intro"><div><p className="eyebrow">OPERATIONAL DATA</p><h2>{view === "integrations" ? "Connected security engines" : pageTitle + " register"}</h2><p>{view === "assets" ? "Inventory returned by the authenticated assets API." : view === "findings" ? "Normalized findings returned by the authenticated findings API." : view === "incidents" ? "Incident records returned by the authenticated incidents API." : "Connection state is read from the backend integration health endpoint."}</p></div></section>}
        {view === "threat-intel" ? <ThreatIntelPanel canOperate={canOperate} /> : view === "detections" ? <DetectionsPanel canOperate={canOperate} isAdmin={user?.role === "admin"} /> : view === "integrations" ? <section className="panel integration-page"><div className="panel-heading"><div><p className="eyebrow">ADAPTER STATUS</p><h3>Engine connectivity</h3></div>{canOperate && <div className="header-actions"><button className="primary-button compact" onClick={handleCollect} disabled={collecting || !wazuh?.configured}>{collecting ? "Collecting Wazuh…" : "Collect Wazuh alerts"}</button><button className="primary-button compact" onClick={handleCollectCrowdSec} disabled={collectingCrowdSec || !crowdsec?.configured}>{collectingCrowdSec ? "Syncing CrowdSec…" : "Sync CrowdSec decisions"}</button></div>}</div><EngineCards wazuh={wazuh} crowdsec={crowdsec} /><NucleiPanel canOperate={canOperate} isAdmin={user.role === "admin"} /><ShannonPanel canOperate={canOperate} isAdmin={user.role === "admin"} /><p className="integration-note">Wazuh collection is read-only. CrowdSec imports active decisions only. Nuclei uses its fixed safe profile. Shannon dispatch requires a separately deployed isolated runner and written authorization.</p></section> :
          <section className="panel data-panel"><div className="panel-heading"><div><p className="eyebrow">DATABASE RECORDS</p><h3>{pageTitle}</h3></div><label className="search-box"><span aria-hidden="true">⌕</span><input aria-label={"Search " + view} value={query} onChange={(event) => setQuery(event.target.value)} placeholder={"Search " + view + "…"} /></label></div><DataTable view={view} assets={assets} findings={findings} incidents={incidents} query={query} user={user} canOperate={canOperate} onFindingStatus={async (id, status) => { try { await updateFindingStatus(id, status); setRefreshKey((value) => value + 1); } catch (reason) { setCollectionError(reason instanceof Error ? reason.message : "Finding update failed."); } }} onIncidentUpdate={async (id, status, resolution, assignToMe) => { try { await updateIncident(id, {status, ...(assignToMe ? {assigned_to_user_id: user.id} : {}), resolution: resolution || undefined}); setRefreshKey((value) => value + 1); } catch (reason) { setCollectionError(reason instanceof Error ? reason.message : "Incident update failed."); } }} /></section>}
      </div>}
      <footer className="app-footer"><span>OPSAEGIS · OPERATIONAL SECURITY & INCIDENT GOVERNANCE</span><span>API v1 <i /> SESSION AUTHENTICATED</span></footer>
    </main>
  </div>;
}

function EngineCards({ wazuh, crowdsec }: { wazuh: WazuhHealth | null; crowdsec: CrowdSecHealth | null }) {
  const engines = [
    { name: "Wazuh Indexer", role: "Read-only SIEM alert ingestion", status: wazuh?.status || "unknown", detail: wazuh?.status === "healthy" ? "Backend health check succeeded" : wazuh?.status === "unhealthy" ? "Backend could not reach the Indexer" : wazuh?.status === "not_configured" ? "Backend credentials or URL not configured" : "Status unavailable" },
    { name: "CrowdSec LAPI", role: "Active threat decisions (read-only)", status: crowdsec?.status || "unknown", detail: crowdsec?.status === "healthy" ? "Authenticated Local API health check succeeded" : crowdsec?.status === "unhealthy" ? "Backend could not authenticate or reach Local API" : crowdsec?.status === "not_configured" ? "Backend URL or bouncer key not configured" : "Status unavailable" },
    { name: "Nuclei", role: "Authorized vulnerability scanning", status: "not_configured", detail: "Safe-profile scanner; configure backend runtime and approved targets" },
    { name: "Shannon", role: "Authorized application security testing", status: "not_configured", detail: "External isolated runner bridge required; disabled by default" },
  ];
  return <div className="engine-grid">{engines.map((engine) => <article className="engine-card" key={engine.name}><div className="engine-card-top"><span className={"engine-indicator " + engine.status} /><span className={"engine-status " + engine.status}>{titleCase(engine.status)}</span></div><h4>{engine.name}</h4><p>{engine.role}</p><small>{engine.detail}</small></article>)}</div>;
}

export default App;

function NucleiPanel({canOperate,isAdmin}:{canOperate:boolean;isAdmin:boolean}) {
 const [health,setHealth]=useState<NucleiHealth|null>(null),[targets,setTargets]=useState<NucleiTarget[]>([]),[scans,setScans]=useState<NucleiScan[]>([]);
 const [name,setName]=useState(""),[url,setUrl]=useState(""),[authorization,setAuthorization]=useState("");
 const [busy,setBusy]=useState(false),[error,setError]=useState(""),[message,setMessage]=useState("");
 async function refresh(){
  const result=await Promise.allSettled([getNucleiHealth(),getNucleiTargets(),getNucleiScans()]);
  if(result[0].status==="fulfilled")setHealth(result[0].value);
  if(result[1].status==="fulfilled")setTargets(result[1].value);
  if(result[2].status==="fulfilled")setScans(result[2].value);
  const failed=result.find(x=>x.status==="rejected");if(failed?.status==="rejected")setError(failed.reason instanceof Error?failed.reason.message:"Unable to load Nuclei data.");
 }
 useEffect(()=>{if(canOperate)void refresh();},[canOperate]);
 async function add(event:FormEvent<HTMLFormElement>){
  event.preventDefault();setBusy(true);setError("");setMessage("");
  try{await registerNucleiTarget({name:name.trim(),url:url.trim(),authorization_reference:authorization.trim()});setName("");setUrl("");setAuthorization("");setMessage("Authorized target registered.");await refresh();}
  catch(e){setError(e instanceof Error?e.message:"Target registration failed.");}finally{setBusy(false);}
 }
 async function scan(id:number){
  setBusy(true);setError("");setMessage("");
  try{const r=await startNucleiScan(id);setMessage("Scan "+r.scan.status+": "+r.received+" results ("+r.inserted+" new, "+r.updated+" updated).");await refresh();}
  catch(e){setError(e instanceof Error?e.message:"Nuclei scan failed.");}finally{setBusy(false);}
 }
 if(!canOperate)return null;
 return <section className="nuclei-workspace">
  <div className="panel-heading"><div><p className="eyebrow">AUTHORIZED VULNERABILITY SCANNING</p><h3>Nuclei scan workspace</h3></div><span className={"engine-status "+(health?.status||"unknown")}>{health?.execution_enabled?"Scanner ready":"Scanner not configured"}</span></div>
  <p className="integration-note">Only admin-registered HTTPS targets with a written authorization reference can be scanned. One fixed safe profile is available; arbitrary CLI arguments and template paths are not accepted.</p>
  {error&&<ErrorMessage>{error}</ErrorMessage>}{message&&<div className="success-banner" role="status">{message}</div>}
  {isAdmin&&<form className="nuclei-target-form" onSubmit={add}>
   <label>Target name<input value={name} onChange={e=>setName(e.target.value)} minLength={2} maxLength={120} required placeholder="Authorized staging application"/></label>
   <label>HTTPS target URL<input type="url" value={url} onChange={e=>setUrl(e.target.value)} required placeholder="https://staging.example.com"/></label>
   <label>Authorization reference<input value={authorization} onChange={e=>setAuthorization(e.target.value)} minLength={12} maxLength={500} required placeholder="Written approval / change ticket"/></label>
   <button className="primary-button compact" disabled={busy}>Register target</button>
  </form>}
  <div className="nuclei-target-list"><h4>Registered targets</h4>{targets.length?targets.map(t=><div className="nuclei-target-row" key={t.id}><div><strong>{t.name}</strong><small>{t.url} · {t.authorization_reference}</small></div><button className="primary-button compact" disabled={busy||!health?.execution_enabled||!t.enabled} onClick={()=>void scan(t.id)}>Run safe scan</button></div>):<EmptyState title="No authorized targets" detail="An administrator must register an approved HTTPS target before scanning."/>}</div>
  <div className="nuclei-target-list"><h4>Recent scan history</h4>{scans.length?scans.slice(0,10).map(s=><div className="nuclei-target-row" key={s.id}><div><strong>Scan #{s.id} · Target #{s.target_id}</strong><small>{s.status} · {s.findings_count} findings · {formatDate(s.created_at)}</small></div><span className="tag">{s.profile}</span></div>):<EmptyState title="No scans yet" detail="Scan execution history will appear here."/>}</div>
  {!health?.execution_enabled&&<p className="integration-note">Execution remains disabled until NUCLEI_ENABLED=true and the Nuclei binary is installed in the backend runtime.</p>}
 </section>;
}
