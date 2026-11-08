import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  ApiError, Asset, Finding, Incident, User, WazuhCollection, WazuhHealth,
  clearAccessToken, collectWazuh, getAccessToken, getAssets, getCurrentUser,
  getFindings, getIncidents, getWazuhHealth, login as loginRequest, saveAccessToken,
} from "./api";

type View = "overview" | "assets" | "findings" | "incidents" | "integrations";
type LoadState = "idle" | "loading" | "ready" | "error";

const navigation: { id: View; label: string; short: string }[] = [
  { id: "overview", label: "Overview", short: "OV" },
  { id: "assets", label: "Assets", short: "AS" },
  { id: "findings", label: "Findings", short: "FI" },
  { id: "incidents", label: "Incidents", short: "IN" },
  { id: "integrations", label: "Integrations", short: "IG" },
];

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}
function titleCase(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
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

function DataTable({ view, assets, findings, incidents, query }: {
  view: View; assets: Asset[]; findings: Finding[]; incidents: Incident[]; query: string;
}) {
  const needle = query.trim().toLowerCase();
  if (view === "assets") {
    const rows = assets.filter((item) => [item.name, item.asset_type, item.environment].join(" ").toLowerCase().includes(needle));
    if (!rows.length) return <EmptyState title={needle ? "No matching assets" : "No assets registered"} detail={needle ? "Try another search term." : "Assets will appear here when they are added through the OpsAegis API."} />;
    return <div className="table-wrap"><table><thead><tr><th>Asset</th><th>Type</th><th>Environment</th><th>Created</th></tr></thead><tbody>{rows.map((item) => <tr key={item.id}><td><strong>{item.name}</strong><small>ASSET-{item.id}</small></td><td>{titleCase(item.asset_type)}</td><td><span className="tag">{titleCase(item.environment)}</span></td><td>{formatDate(item.created_at)}</td></tr>)}</tbody></table></div>;
  }
  if (view === "findings") {
    const rows = findings.filter((item) => [item.title, item.source_engine, item.status, item.severity].join(" ").toLowerCase().includes(needle));
    if (!rows.length) return <EmptyState title={needle ? "No matching findings" : "No findings recorded"} detail={needle ? "Try another search term." : "Findings appear after a security engine sends verified events or an authorized analyst records one."} />;
    return <div className="table-wrap"><table><thead><tr><th>Finding</th><th>Source</th><th>Severity</th><th>Status</th><th>Last seen</th></tr></thead><tbody>{rows.map((item) => <tr key={item.id}><td><strong>{item.title}</strong><small>FINDING-{item.id}{item.asset_id ? " · ASSET-" + item.asset_id : ""}</small></td><td>{titleCase(item.source_engine)}</td><td><span className={severityClass(item.severity)}>{titleCase(item.severity)}</span></td><td><span className="tag">{titleCase(item.status)}</span></td><td>{formatDate(item.last_seen_at)}</td></tr>)}</tbody></table></div>;
  }
  const rows = incidents.filter((item) => [item.title, item.status, item.severity].join(" ").toLowerCase().includes(needle));
  if (!rows.length) return <EmptyState title={needle ? "No matching incidents" : "No incidents recorded"} detail={needle ? "Try another search term." : "Incidents created in OpsAegis will appear here. No incidents are generated automatically yet."} />;
  return <div className="table-wrap"><table><thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Created</th></tr></thead><tbody>{rows.map((item) => <tr key={item.id}><td><strong>{item.title}</strong><small>INCIDENT-{item.id}</small></td><td><span className={severityClass(item.severity)}>{titleCase(item.severity)}</span></td><td><span className="tag">{titleCase(item.status)}</span></td><td>{formatDate(item.created_at)}</td></tr>)}</tbody></table></div>;
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
  const [loadState, setLoadState] = useState<LoadState>("idle");
  const [loadErrors, setLoadErrors] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);
  const [collecting, setCollecting] = useState(false);
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
    ];
    Promise.allSettled(requests).then((results) => {
      if (!active) return;
      const errors: string[] = [];
      const [assetResult, findingResult, incidentResult, wazuhResult] = results;
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
        <section className="welcome-row"><div><p className="eyebrow">OPERATIONAL SNAPSHOT</p><h2>Security posture at a glance.</h2><p>Live records retrieved from your OpsAegis database. No demo metrics or synthetic telemetry are included.</p></div><div className="snapshot-stamp"><span className="live-dot" /> DATABASE CONNECTED <small>{loadState === "ready" ? "LATEST API READ COMPLETE" : "WAITING FOR API"}</small></div></section>
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
        <section className="panel engine-panel"><div className="panel-heading"><div><p className="eyebrow">INTEGRATION LAYER</p><h3>Security engines</h3></div><button className="text-button" onClick={() => setView("integrations")}>Integration details <span>→</span></button></div><EngineCards wazuh={wazuh} /></section>
      </div>}

      {view !== "overview" && <div className="page-content">
        <section className="list-intro"><div><p className="eyebrow">OPERATIONAL DATA</p><h2>{view === "integrations" ? "Connected security engines" : pageTitle + " register"}</h2><p>{view === "assets" ? "Inventory returned by the authenticated assets API." : view === "findings" ? "Normalized findings returned by the authenticated findings API." : view === "incidents" ? "Incident records returned by the authenticated incidents API." : "Connection state is read from the backend integration health endpoint."}</p></div></section>
        {view === "integrations" ? <section className="panel integration-page"><div className="panel-heading"><div><p className="eyebrow">ADAPTER STATUS</p><h3>Engine connectivity</h3></div>{canOperate && <button className="primary-button compact" onClick={handleCollect} disabled={collecting || !wazuh?.configured}>{collecting ? "Collecting…" : "Collect Wazuh alerts"}</button>}</div><EngineCards wazuh={wazuh} /><p className="integration-note">Wazuh collection is read-only. Collection is enabled only when the backend reports a configured Indexer connection. CrowdSec, Nuclei and Shannon are not represented as connected.</p></section> :
          <section className="panel data-panel"><div className="panel-heading"><div><p className="eyebrow">DATABASE RECORDS</p><h3>{pageTitle}</h3></div><label className="search-box"><span aria-hidden="true">⌕</span><input aria-label={"Search " + view} value={query} onChange={(event) => setQuery(event.target.value)} placeholder={"Search " + view + "…"} /></label></div><DataTable view={view} assets={assets} findings={findings} incidents={incidents} query={query} /></section>}
      </div>}
      <footer className="app-footer"><span>OPSAEGIS · OPERATIONAL SECURITY & INCIDENT GOVERNANCE</span><span>API v1 <i /> SESSION AUTHENTICATED</span></footer>
    </main>
  </div>;
}

function EngineCards({ wazuh }: { wazuh: WazuhHealth | null }) {
  const engines = [
    { name: "Wazuh Indexer", role: "Read-only SIEM alert ingestion", status: wazuh?.status || "unknown", detail: wazuh?.status === "healthy" ? "Backend health check succeeded" : wazuh?.status === "unhealthy" ? "Backend could not reach the Indexer" : wazuh?.status === "not_configured" ? "Backend credentials or URL not configured" : "Status unavailable" },
    { name: "CrowdSec", role: "Threat intelligence and decisions", status: "planned", detail: "Adapter not implemented" },
    { name: "Nuclei", role: "Authorized vulnerability scanning", status: "planned", detail: "Adapter not implemented" },
    { name: "Shannon", role: "Authorized application security testing", status: "planned", detail: "Adapter not implemented" },
  ];
  return <div className="engine-grid">{engines.map((engine) => <article className="engine-card" key={engine.name}><div className="engine-card-top"><span className={"engine-indicator " + engine.status} /><span className={"engine-status " + engine.status}>{titleCase(engine.status)}</span></div><h4>{engine.name}</h4><p>{engine.role}</p><small>{engine.detail}</small></article>)}</div>;
}

export default App;
