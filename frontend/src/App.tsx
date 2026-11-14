import type { FormEvent } from "react";
import { useEffect, useMemo, useState } from "react";
import { OpsAegisSignIn } from "./OpsAegisSignIn";
import { AdminUsers } from "./AdminUsers";
import { ShannonPanel } from "./ShannonPanel";
import { DetectionsPanel } from "./DetectionsPanel";
import { ThreatIntelPanel } from "./ThreatIntelPanel";
import { VulnerabilityPanel } from "./VulnerabilityPanel";
import { CollectionPanel } from "./CollectionPanel";
import { IncidentTimeline } from "./IncidentTimeline";
import { OperationsPanel } from "./OperationsPanel";
import { ExecutionLedgerPanel } from "./ExecutionLedgerPanel";
import { PlaybooksPanel } from "./PlaybooksPanel";
import { AppDashboardShell } from "./components/ui/app-dashboard-shell";
import { SecurityOverviewBento } from "./components/ui/security-overview-bento";
import { SectionInsights } from "./components/ui/section-insights";
import { PrismFluxLoader } from "./components/ui/prism-flux-loader";
import { ThemeToggle, type ThemeMode } from "./components/ui/theme-toggle";
import "./components/ui/prism-flux-loader.css";
import { NucleiHealth, NucleiTarget, NucleiScan, getNucleiHealth, getNucleiTargets, getNucleiScans, registerNucleiTarget, startNucleiScan, ShannonHealth, getShannonHealth } from "./api";
import { describeEngineHealth } from "./engineHealth";
import {
  ApiError, Asset, Finding, Incident, User, WazuhCollection, WazuhHealth, WazuhManagerHealth, WazuhManagerSync, CrowdSecCollection, CrowdSecHealth, collectCrowdSec, getCrowdSecHealth, getWazuhManagerHealth, syncWazuhManager,
  clearAccessToken, collectWazuh, createAsset, createIncident, getAccessToken, getAssets, getCurrentUser,
  getFindings, getIncidents, getWazuhHealth, getDetections, Detection, login as loginRequest, saveAccessToken, updateFindingStatus, updateIncident,
} from "./api";

type View = "overview" | "assets" | "findings" | "vulnerabilities" | "detections" | "incidents" | "integrations" | "threat-intel" | "playbooks" | "users" | "reports" | "settings";
type LoadState = "idle" | "loading" | "ready" | "error";

const navigation: { id: View; label: string; short: string }[] = [
  { id: "overview", label: "Overview", short: "OV" },
  { id: "assets", label: "Assets", short: "AS" },
  { id: "findings", label: "Findings", short: "FI" },
  { id: "vulnerabilities", label: "Vulnerabilities", short: "VU" },
  { id: "detections", label: "Detections", short: "DE" },
  { id: "incidents", label: "Incidents", short: "IN" },
  { id: "integrations", label: "Integrations", short: "IG" },
  { id: "threat-intel", label: "Threat Intel", short: "TI" },
  { id: "playbooks", label: "Playbooks", short: "PB" },
  { id: "users", label: "Users & roles", short: "UR" },
  { id: "reports", label: "Reports", short: "RP" },
  { id: "settings", label: "Settings", short: "ST" },
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

type ThemePreference = "dark" | "light" | "system";


function StatCard({ label, value, detail, accent }: { label: string; value: number; detail: string; accent: string }) {
  return <article className="stat-card">
    <div className="stat-heading"><span>{label}</span><i className={"stat-accent " + accent} /></div>
    <strong className="stat-value">{value.toLocaleString()}</strong>
    <span className="stat-detail">{detail}</span>
  </article>;
}

function DataTable({ view, assets, findings, incidents, query, user, canOperate, onFindingStatus, onIncidentUpdate, onIncidentCreated, onAssetCreated }: {
  view: View; assets: Asset[]; findings: Finding[]; incidents: Incident[]; query: string;
  user: User; canOperate: boolean;
  onFindingStatus: (id: number, status: Finding["status"]) => void;
  onIncidentUpdate: (id: number, status: Incident["status"], resolution: string, assignToMe?: boolean) => void;
  onIncidentCreated: () => void;
  onAssetCreated: () => void;
}) {
  const [newAssetName, setNewAssetName] = useState("");
  const [newAssetType, setNewAssetType] = useState("endpoint");
  const [newAssetEnvironment, setNewAssetEnvironment] = useState("unknown");
  const [creatingAsset, setCreatingAsset] = useState(false);
  const [createAssetError, setCreateAssetError] = useState("");
  const [createAssetNotice, setCreateAssetNotice] = useState("");
  const [resolutionNotes, setResolutionNotes] = useState<Record<number, string>>({});
  const [incidentStatuses, setIncidentStatuses] = useState<Record<number, Incident["status"]>>({});
  const [assetStatus, setAssetStatus] = useState("all");
  const [assetEnvironment, setAssetEnvironment] = useState("all");
  const [assetSource, setAssetSource] = useState("all");
  const [incidentDetections, setIncidentDetections] = useState<Detection[]>([]);
  const [incidentDetectionsError, setIncidentDetectionsError] = useState("");
  const [expandedIncidentIds, setExpandedIncidentIds] = useState<number[]>([]);
  const [newIncidentTitle, setNewIncidentTitle] = useState("");
  const [newIncidentSeverity, setNewIncidentSeverity] = useState<Incident["severity"]>("medium");
  const [newIncidentDescription, setNewIncidentDescription] = useState("");
  const [creatingIncident, setCreatingIncident] = useState(false);
  const [createIncidentError, setCreateIncidentError] = useState("");
  useEffect(() => {
    if (view !== "incidents") return;
    let active = true;
    getDetections().then((items) => {
      if (active) { setIncidentDetections(items); setIncidentDetectionsError(""); }
    }).catch((reason: unknown) => {
      if (active) setIncidentDetectionsError(reason instanceof Error ? reason.message : "Linked detections could not be loaded.");
    });
    return () => { active = false; };
  }, [view]);
  const needle = query.trim().toLowerCase();
  if (view === "assets") {
    const registeredAgents = assets.filter((item) => Boolean(item.source_engine && item.external_id));
    const reportedOnline = registeredAgents.filter((item) => ["active", "connected", "online"].includes((item.agent_status || "").toLowerCase())).length;
    const reportedOffline = registeredAgents.filter((item) => ["disconnected", "offline", "never_connected"].includes((item.agent_status || "").toLowerCase())).length;
    const environments = [...new Set(assets.map((item) => item.environment).filter(Boolean))].sort();
    const sources = [...new Set(assets.map((item) => item.source_engine || "manual"))].sort();
    const rows = assets.filter((item) => {
      const matchesSearch = [item.name, item.asset_type, item.environment, item.os_name || "", item.agent_status || "", item.external_id || "", item.ip_address || ""].join(" ").toLowerCase().includes(needle);
      const matchesStatus = assetStatus === "all" || (item.agent_status || "unknown").toLowerCase() === assetStatus;
      const matchesEnvironment = assetEnvironment === "all" || item.environment === assetEnvironment;
      const matchesSource = assetSource === "all" || (item.source_engine || "manual") === assetSource;
      return matchesSearch && matchesStatus && matchesEnvironment && matchesSource;
    });
    async function handleCreateAsset(event: FormEvent<HTMLFormElement>) {
      event.preventDefault();
      setCreatingAsset(true);
      setCreateAssetError("");
      setCreateAssetNotice("");
      try {
        await createAsset({
          name: newAssetName.trim(),
          asset_type: newAssetType,
          environment: newAssetEnvironment,
        });
        setNewAssetName("");
        setNewAssetType("endpoint");
        setNewAssetEnvironment("unknown");
        setCreateAssetNotice("Asset registered successfully.");
        onAssetCreated();
      } catch (reason) {
        setCreateAssetError(reason instanceof Error ? reason.message : "Asset registration failed.");
      } finally {
        setCreatingAsset(false);
      }
    }
    return <div className="asset-workspace">
      {canOperate && <section className="nuclei-workspace">
        <div className="panel-heading"><div><p className="eyebrow">MANUAL INVENTORY</p><h3>Register an asset</h3></div></div>
        <p className="integration-note">Use this for assets not yet discovered through Wazuh. Wazuh-managed records remain source-managed.</p>
        {createAssetError && <div className="error-banner" role="alert">{createAssetError}</div>}
        {createAssetNotice && <div className="success-banner" role="status">{createAssetNotice}</div>}
        <form className="nuclei-target-form" onSubmit={handleCreateAsset}>
          <label>Asset name<input required minLength={1} maxLength={255} value={newAssetName} onChange={event => setNewAssetName(event.target.value)} placeholder="Production API server"/></label>
          <label>Asset type<select value={newAssetType} onChange={event => setNewAssetType(event.target.value)}><option value="endpoint">Endpoint</option><option value="server">Server</option><option value="web_application">Web application</option><option value="network_device">Network device</option><option value="database">Database</option><option value="cloud_resource">Cloud resource</option><option value="other">Other</option></select></label>
          <label>Environment<select value={newAssetEnvironment} onChange={event => setNewAssetEnvironment(event.target.value)}><option value="unknown">Unknown</option><option value="production">Production</option><option value="staging">Staging</option><option value="development">Development</option><option value="testing">Testing</option><option value="lab">Lab</option></select></label>
          <button className="primary-button compact" disabled={creatingAsset || !newAssetName.trim()}>{creatingAsset ? "Registering…" : "Register asset"}</button>
        </form>
      </section>}
      <div className="asset-summary">
        <article><small>INVENTORY RECORDS</small><strong>{assets.length}</strong><span>Returned by API · max 200</span></article>
        <article><small>WAZUH-MAPPED AGENTS</small><strong>{registeredAgents.length}</strong><span>Identified by source and agent ID</span></article>
        <article><small>REPORTED ONLINE</small><strong>{reportedOnline}</strong><span>Based on reported agent status</span></article>
        <article><small>REPORTED OFFLINE</small><strong>{reportedOffline}</strong><span>Unknown states are not counted</span></article>
      </div>
      <div className="asset-filters">
        <label>Agent status<select value={assetStatus} onChange={(event) => setAssetStatus(event.target.value)}><option value="all">All statuses</option><option value="active">Active</option><option value="connected">Connected</option><option value="online">Online</option><option value="disconnected">Disconnected</option><option value="offline">Offline</option><option value="unknown">Unknown / not reported</option></select></label>
        <label>Environment<select value={assetEnvironment} onChange={(event) => setAssetEnvironment(event.target.value)}><option value="all">All environments</option>{environments.map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}</select></label>
        <label>Source<select value={assetSource} onChange={(event) => setAssetSource(event.target.value)}><option value="all">All sources</option>{sources.map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}</select></label>
        <span className="asset-result-count">{rows.length} of {assets.length} records</span>
        <button className="text-button" onClick={() => { setAssetStatus("all"); setAssetEnvironment("all"); setAssetSource("all"); }}>Clear filters</button>
      </div>
      {!rows.length ? <EmptyState title={assets.length ? "No matching assets" : "No assets registered"} detail={assets.length ? "Adjust or clear the filters to see more endpoint records." : "Assets will appear here when they are added through the OpsAegis API."} /> :
      <div className="table-wrap"><table><thead><tr><th>Asset</th><th>Type</th><th>IP address</th><th>Agent source</th><th>Operating system</th><th>Agent status</th><th>Environment</th><th>Last observed</th></tr></thead><tbody>{rows.map((item) => <tr key={item.id}><td><strong>{item.name}</strong><small>ASSET-{item.id}</small></td><td>{titleCase(item.asset_type)}</td><td>{item.ip_address ?? "—"}</td><td>{item.source_engine ? titleCase(item.source_engine) + (item.external_id ? " · " + item.external_id : "") : "Manual"}</td><td>{item.os_name ?? "—"}</td><td>{item.agent_status ? <span className="tag">{titleCase(item.agent_status)}</span> : "Not reported"}</td><td><span className="tag">{titleCase(item.environment)}</span></td><td>{item.last_seen_at ? formatDate(item.last_seen_at) : "—"}</td></tr>)}</tbody></table></div>}
    </div>;
  }
  if (view === "findings") {
    const rows = findings.filter((item) => [item.title, item.source_engine, item.status, item.severity].join(" ").toLowerCase().includes(needle));
    if (!rows.length) return <EmptyState title={needle ? "No matching findings" : "No findings recorded"} detail={needle ? "Try another search term." : "Findings appear after a security engine sends verified events or an authorized analyst records one."} />;
    return <div className="table-wrap"><table><thead><tr><th>Finding</th><th>Source</th><th>Severity</th><th>Status</th><th>Last seen</th></tr></thead><tbody>{rows.map((item) => <tr key={item.id}><td><strong>{item.title}</strong><small>FINDING-{item.id}{item.asset_id ? " · ASSET-" + item.asset_id : ""}</small></td><td>{titleCase(item.source_engine)}</td><td><span className={severityClass(item.severity)}>{titleCase(item.severity)}</span></td><td>{canOperate ? <select aria-label={"Update finding " + item.id + " status"} value={item.status} onChange={(event) => onFindingStatus(item.id, event.target.value as Finding["status"])}>{["new","triaged","accepted","false_positive","resolved"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}</select> : <span className="tag">{titleCase(item.status)}</span>}</td><td>{formatDate(item.last_seen_at)}</td></tr>)}</tbody></table></div>;
  }
  const rows = incidents.filter((item) => [item.title, item.status, item.severity, item.description || "", item.resolution || ""].join(" ").toLowerCase().includes(needle));
  return <div className="incident-workspace">
    <div className="incident-summary">
      <article><small>RETURNED INCIDENTS</small><strong>{incidents.length}</strong><span>API records · max 200</span></article>
      <article><small>OPEN / INVESTIGATING</small><strong>{incidents.filter((item) => ["open", "investigating"].includes(item.status)).length}</strong><span>Active response states</span></article>
      <article><small>CONTAINED</small><strong>{incidents.filter((item) => item.status === "contained").length}</strong><span>Containment recorded</span></article>
      <article><small>RESOLVED / CLOSED</small><strong>{incidents.filter((item) => ["resolved", "closed"].includes(item.status)).length}</strong><span>Completed lifecycle states</span></article>
    </div>
    {canOperate && <form className="panel incident-create-form" onSubmit={async (event) => {
      event.preventDefault();
      if (!newIncidentTitle.trim()) return;
      setCreatingIncident(true); setCreateIncidentError("");
      try {
        await createIncident({title:newIncidentTitle.trim(),severity:newIncidentSeverity,description:newIncidentDescription.trim() || undefined});
        setNewIncidentTitle(""); setNewIncidentDescription(""); setNewIncidentSeverity("medium");
        onIncidentCreated();
      } catch (reason) {
        setCreateIncidentError(reason instanceof Error ? reason.message : "Incident creation failed.");
      } finally { setCreatingIncident(false); }
    }}>
      <div className="panel-heading"><div><p className="eyebrow">CASE MANAGEMENT</p><h3>Create incident</h3></div></div>
      {createIncidentError && <ErrorMessage>{createIncidentError}</ErrorMessage>}
      <div className="incident-actions">
        <label>Incident title<input value={newIncidentTitle} onChange={(event)=>setNewIncidentTitle(event.target.value)} maxLength={500} required placeholder="Describe the security incident"/></label>
        <label>Severity<select value={newIncidentSeverity} onChange={(event)=>setNewIncidentSeverity(event.target.value as Incident["severity"])}>{["critical","high","medium","low","informational","unknown"].map(value=><option key={value} value={value}>{titleCase(value)}</option>)}</select></label>
        <label className="resolution-field">Description<textarea rows={2} maxLength={10000} value={newIncidentDescription} onChange={(event)=>setNewIncidentDescription(event.target.value)} placeholder="Add initial context and evidence references"/></label>
        <button className="primary-button compact" type="submit" disabled={creatingIncident || !newIncidentTitle.trim()}>{creatingIncident?"Creating…":"Create incident"}</button>
      </div>
    </form>}
    {!rows.length && <EmptyState title={needle ? "No matching incidents" : "No incidents recorded"} detail={needle ? "Try another search term or clear the search." : "Create an incident above, or connect an event source to generate incidents from detections."} />}
    {incidentDetectionsError && <div className="inline-error" role="status">Linked detection context unavailable: {incidentDetectionsError}</div>}
    <div className="incident-register">{rows.map((item) => {
      const expanded = expandedIncidentIds.includes(item.id);
      const linkedDetections = incidentDetections.filter((detection) => detection.incident_id === item.id);
      const linkedFindingIds = [...new Set(linkedDetections.flatMap((detection) => detection.finding_ids))];
      const linkedFindings = linkedFindingIds.map((id) => findings.find((finding) => finding.id === id)).filter((finding): finding is Finding => Boolean(finding));
      const unresolvedFindingIds = linkedFindingIds.filter((id) => !findings.some((finding) => finding.id === id));
      return <article className="incident-card" key={item.id}>
        <div className="incident-card-head">
          <div className="incident-card-title"><span className="incident-id">INCIDENT-{item.id}</span><h3>{item.title}</h3><div className="incident-meta"><span className={severityClass(item.severity)}>{titleCase(item.severity)}</span><span className="tag">{titleCase(item.status)}</span><span>Created {formatDate(item.created_at)}</span></div></div>
          <button className="secondary-button" aria-expanded={expanded} onClick={() => setExpandedIncidentIds((current) => expanded ? current.filter((id) => id !== item.id) : [...current, item.id])}>{expanded ? "Hide investigation" : "Investigate incident"}</button>
        </div>
        {canOperate && <div className="incident-actions incident-card-actions">
          <label>Status<select aria-label={"Update incident " + item.id + " status"} value={incidentStatuses[item.id] ?? item.status} onChange={(event) => setIncidentStatuses((current) => ({...current,[item.id]:event.target.value as Incident["status"]}))}>{["open","investigating","contained","resolved","closed"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}</select></label>
          <label className="resolution-field">Resolution / analyst notes<input aria-label={"Resolution note for incident " + item.id} value={resolutionNotes[item.id] ?? item.resolution ?? ""} onChange={(event) => setResolutionNotes((current) => ({...current,[item.id]:event.target.value}))} placeholder="Required before resolving or closing" maxLength={10000}/></label>
          <button className="primary-button compact" onClick={() => onIncidentUpdate(item.id, incidentStatuses[item.id] ?? item.status, resolutionNotes[item.id] ?? item.resolution ?? "")}>Save changes</button>
          <button className="text-button" title={"Assign incident to " + user.email} onClick={() => onIncidentUpdate(item.id, incidentStatuses[item.id] ?? item.status, resolutionNotes[item.id] ?? item.resolution ?? "", true)}>Assign to me</button>
        </div>}
        {expanded && <div className="incident-investigation">
          <section><h4>Incident description</h4><p>{item.description || "No incident description was recorded."}</p></section>
          <section><h4>Response record</h4><dl><div><dt>Assigned analyst ID</dt><dd>{item.assigned_to_user_id ?? "Unassigned"}</dd></div><div><dt>Last updated</dt><dd>{formatDate(item.updated_at)}</dd></div><div><dt>Closed at</dt><dd>{item.closed_at ? formatDate(item.closed_at) : "Not closed"}</dd></div></dl><p className="incident-resolution">{item.resolution || "No resolution note recorded."}</p></section>
          <section><h4>Correlated detections <span>{linkedDetections.length}</span></h4>{linkedDetections.length ? linkedDetections.map((detection) => <div className="linked-evidence-row" key={detection.id}><div><strong>{detection.title}</strong><small>{detection.rule_key} · {titleCase(detection.status)} · {detection.finding_ids.length} linked finding IDs</small></div><span className={severityClass(detection.severity)}>{titleCase(detection.severity)}</span></div>) : <p>No linked detections are present in the currently returned detection records.</p>}</section>
          <section><h4>Evidence findings <span>{linkedFindingIds.length}</span></h4>{linkedFindings.length ? linkedFindings.map((finding) => <div className="linked-evidence-row" key={finding.id}><div><strong>{finding.title}</strong><small>FINDING-{finding.id} · {titleCase(finding.source_engine)} · {titleCase(finding.status)}</small>{finding.description && <p>{finding.description}</p>}{finding.evidence_uri && <small>Evidence reference: {finding.evidence_uri}</small>}</div><span className={severityClass(finding.severity)}>{titleCase(finding.severity)}</span></div>) : <p>No linked finding details are available in the current findings result set.</p>}{unresolvedFindingIds.length > 0 && <p className="integration-note">{unresolvedFindingIds.length} linked finding ID(s) are outside the currently loaded findings result set.</p>}</section>
          <IncidentTimeline incidentId={item.id} canOperate={canOperate} />
        </div>}
      </article>;
    })}</div>
  </div>;
}

function SeverityBreakdown({ findings }: { findings: Finding[] }) {
  const levels = [
    { key: "critical", label: "Critical" },
    { key: "high", label: "High" },
    { key: "medium", label: "Medium" },
    { key: "low", label: "Low" },
    { key: "informational", label: "Informational" },
  ] as const;
  const counts = levels.map((level) => ({
    ...level,
    count: findings.filter((finding) => finding.severity.toLowerCase() === level.key).length,
  }));
  const total = counts.reduce((sum, level) => sum + level.count, 0);
  return <section className="panel severity-panel" aria-label="Finding severity distribution">
    <div className="panel-heading">
      <div><p className="eyebrow">FINDING TRIAGE</p><h3>Severity distribution</h3></div>
      <span className="distribution-total">{total.toLocaleString()} returned findings</span>
    </div>
    {total ? <div className="severity-breakdown">
      {counts.map((level) => <div className="severity-line" key={level.key}>
        <div className="severity-line-label"><span className={"severity-dot " + level.key} /><span>{level.label}</span><strong>{level.count.toLocaleString()}</strong></div>
        <div className="severity-track" role="progressbar" aria-label={level.label + " findings"} aria-valuemin={0} aria-valuemax={total} aria-valuenow={level.count}>
          <span className={"severity-fill " + level.key} style={{ width: ((level.count / total) * 100).toFixed(2) + "%" }} />
        </div>
      </div>)}
    </div> : <EmptyState title="No severity data yet" detail="Verified findings will populate this distribution after ingestion." />}
    <p className="distribution-footnote">Distribution is calculated from the findings currently returned by the API (maximum 200 records), not an unbounded database total.</p>
  </section>;
}

function App() {
  const [theme, setTheme] = useState<ThemePreference>(() => {
    try {
      const saved = window.localStorage.getItem("opsaegis-theme");
      return saved === "light" || saved === "system" ? saved : "dark";
    } catch {
      return "dark";
    }
  });
  const [systemTheme, setSystemTheme] = useState<ThemeMode>(() => {
    try { return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"; }
    catch { return "dark"; }
  });
  const resolvedTheme: ThemeMode = theme === "system" ? systemTheme : theme;

  useEffect(() => {
    const applyTheme = () => {
      const resolved: ThemeMode = theme === "system"
        ? (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")
        : theme;
      document.documentElement.dataset.theme = resolved;
      document.documentElement.classList.toggle("dark", resolved === "dark");
      setSystemTheme((current) => current === resolved ? current : resolved);
    };
    applyTheme();
    try { window.localStorage.setItem("opsaegis-theme", theme); } catch { /* storage may be unavailable */ }
    if (theme !== "system") return;
    const preference = window.matchMedia("(prefers-color-scheme: light)");
    preference.addEventListener("change", applyTheme);
    return () => preference.removeEventListener("change", applyTheme);
  }, [theme]);

  function handleThemeChange(next: ThemeMode, trigger: HTMLButtonElement) {
    setTheme(next);
    const root = document.documentElement;
    const doc = document as Document & {
      startViewTransition?: (update: () => void) => { finished: Promise<void> };
    };
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reducedMotion || !doc.startViewTransition) {
      root.dataset.theme = next;
      return;
    }
    const rect = trigger.getBoundingClientRect();
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;
    const radius = Math.max(
      Math.hypot(x, y),
      Math.hypot(window.innerWidth - x, y),
      Math.hypot(x, window.innerHeight - y),
      Math.hypot(window.innerWidth - x, window.innerHeight - y),
    );
    root.style.setProperty("--aegis-theme-origin", `${x}px ${y}px`);
    root.style.setProperty("--aegis-theme-radius", `${radius}px`);
    const cleanup = () => {
      root.style.removeProperty("--aegis-theme-origin");
      root.style.removeProperty("--aegis-theme-radius");
    };
    try {
      const transition = doc.startViewTransition(() => { root.dataset.theme = next; });
      void transition.finished.then(cleanup, cleanup);
    } catch {
      root.dataset.theme = next;
      cleanup();
    }
  }
  const [token, setToken] = useState<string | null>(() => getAccessToken());
  const [user, setUser] = useState<User | null>(null);
  const [authState, setAuthState] = useState<LoadState>("idle");
  const [postLoginTransition, setPostLoginTransition] = useState(false);
  const [view, setView] = useState<View>("overview");
  const [assets, setAssets] = useState<Asset[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [wazuh, setWazuh] = useState<WazuhHealth | null>(null);
  const [wazuhManager,setWazuhManager]=useState<WazuhManagerHealth|null>(null);
  const [crowdsec, setCrowdsec] = useState<CrowdSecHealth | null>(null);
  const [loadState, setLoadState] = useState<LoadState>("idle");
  const [loadErrors, setLoadErrors] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);
  const [collecting, setCollecting] = useState(false);
  const [collectingCrowdSec, setCollectingCrowdSec] = useState(false);
  const [syncingWazuhManager,setSyncingWazuhManager]=useState(false);
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
    if (!postLoginTransition || !user) return;
    const transitionTimer = window.setTimeout(() => setPostLoginTransition(false), 1000);
    return () => window.clearTimeout(transitionTimer);
  }, [postLoginTransition, user]);

  useEffect(() => {
    if (!user) return;
    let active = true;
    setLoadState("loading");
    setLoadErrors([]);
    const requests: Promise<unknown>[] = [
      getAssets(), getFindings(), getIncidents(),
      canOperate ? getWazuhHealth() : Promise.resolve(null),
      canOperate ? getCrowdSecHealth() : Promise.resolve(null),
      canOperate ? getWazuhManagerHealth() : Promise.resolve(null),
    ];
    Promise.allSettled(requests).then((results) => {
      if (!active) return;
      const errors: string[] = [];
      const [assetResult, findingResult, incidentResult, wazuhResult, crowdsecResult, wazuhManagerResult] = results;
      if (assetResult.status === "fulfilled") setAssets(assetResult.value as Asset[]);
      else errors.push("Assets: " + (assetResult.reason instanceof Error ? assetResult.reason.message : "Unable to load assets."));
      if (findingResult.status === "fulfilled") setFindings(findingResult.value as Finding[]);
      else errors.push("Findings: " + (findingResult.reason instanceof Error ? findingResult.reason.message : "Unable to load findings."));
      if (incidentResult.status === "fulfilled") setIncidents(incidentResult.value as Incident[]);
      else errors.push("Incidents: " + (incidentResult.reason instanceof Error ? incidentResult.reason.message : "Unable to load incidents."));
      if (wazuhResult.status === "fulfilled") setWazuh(wazuhResult.value as WazuhHealth | null);
      else errors.push("Wazuh status: " + (wazuhResult.reason instanceof Error ? wazuhResult.reason.message : "Unable to load integration status."));
      if(wazuhManagerResult.status==="fulfilled")setWazuhManager(wazuhManagerResult.value as WazuhManagerHealth|null);
      else errors.push("Wazuh Manager status: "+(wazuhManagerResult.reason instanceof Error?wazuhManagerResult.reason.message:"Unable to load Manager status."));
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
    setPostLoginTransition(true);
    setToken(result.access_token);
    setView("overview");
    setQuery("");
    setLoadErrors([]);
  }
  function handleLogout() {
    clearAccessToken();
    setPostLoginTransition(false);
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

  async function handleWazuhManagerSync(){
    setSyncingWazuhManager(true);setCollectionError("");setCollectionMessage("");
    try{const result:WazuhManagerSync=await syncWazuhManager();setCollectionMessage("Wazuh Manager inventory sync: "+result.received+" received, "+result.created+" new, "+result.updated+" updated, "+result.unchanged+" unchanged."+(result.truncated_possible?" Result limit reached; some agents may remain unsynchronized.":""));setRefreshKey(value=>value+1);}
    catch(reason){setCollectionError(reason instanceof Error?reason.message:"Wazuh Manager agent sync failed.");}
    finally{setSyncingWazuhManager(false);}
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

  if (postLoginTransition && user) return <PrismFluxLoader size={64} speed={5} textSize={28} />;
  if (authState === "loading" || (token && !user && authState !== "idle")) {
    return <PrismFluxLoader size={64} speed={5} textSize={28} />;
  }
  if (!token || !user) return <OpsAegisSignIn onLogin={handleLogin} theme={resolvedTheme} onThemeChange={setTheme} />;

  return <AppDashboardShell
    workspace={{ name: "OpsAegis", plan: "Security Operations" }}
    user={{ name: user.email, email: user.email, role: user.role }}
    nav={navigation.filter((item) => (item.id !== "playbooks" || canOperate) && (item.id !== "users" || user.role === "admin")).map((item) => ({ ...item, badge: item.id === "findings" && filteredFindingCount > 0 ? String(filteredFindingCount) : undefined }))}
    activeId={view}
    onNavigate={(id) => { setView(id as View); setQuery(""); }}
    onLogout={handleLogout}
    showSearch={view === "assets" || view === "findings" || view === "incidents"}
    searchValue={query}
    onSearchChange={setQuery}
    headerActions={<>
      <ThemeToggle mode={resolvedTheme} onModeChange={handleThemeChange} responsive />
      <span className="aegis-role-chip">{titleCase(user.role)}</span>
      <button className="aegis-refresh" onClick={() => setRefreshKey((value) => value + 1)} disabled={loadState === "loading"}><span aria-hidden="true">↻</span> Refresh</button>
    </>}
  >
      {loadState === "loading" && <div className="loading-banner"><span className="spinner" /> Syncing records from OpsAegis API…</div>}
      {loadErrors.length > 0 && <div className="error-banner" role="alert"><strong>Some data could not be loaded.</strong>{loadErrors.map((error) => <span key={error}>{error}</span>)}</div>}
      {collectionMessage && <div className="success-banner" role="status">{collectionMessage}</div>}
      {collectionError && <div className="error-banner" role="alert">{collectionError}</div>}

      {view === "overview" && <div className="page-content">
        
        <SecurityOverviewBento assets={assets} findings={findings} incidents={incidents} refreshKey={refreshKey} />
        <OperationsPanel isAdmin={user.role === "admin"} refreshKey={refreshKey} />
        {canOperate && <ExecutionLedgerPanel refreshKey={refreshKey} />}
        <section className="overview-grid">
          <article className="panel"><div className="panel-heading"><div><p className="eyebrow">LATEST ACTIVITY</p><h3>Recent findings</h3></div><button className="text-button" onClick={() => setView("findings")}>View all <span>→</span></button></div>
            {findings.length ? <div className="activity-list">{findings.slice(0, 5).map((item) => <div className="activity-row" key={item.id}><span className={"activity-icon " + item.severity}>{item.severity === "critical" || item.severity === "high" ? "!" : "•"}</span><div className="activity-copy"><strong>{item.title}</strong><small>{titleCase(item.source_engine)} · {formatDate(item.last_seen_at)}</small></div><span className={severityClass(item.severity)}>{titleCase(item.severity)}</span></div>)}</div> : <EmptyState title="No findings yet" detail="Verified findings will be listed here." />}
          </article>
          <article className="panel"><div className="panel-heading"><div><p className="eyebrow">RESPONSE WORKFLOW</p><h3>Recent incidents</h3></div><button className="text-button" onClick={() => setView("incidents")}>View all <span>→</span></button></div>
            {incidents.length ? <div className="activity-list">{incidents.slice(0, 5).map((item) => <div className="activity-row" key={item.id}><span className="incident-icon">↗</span><div className="activity-copy"><strong>{item.title}</strong><small>{titleCase(item.status)} · {formatDate(item.created_at)}</small></div><span className={severityClass(item.severity)}>{titleCase(item.severity)}</span></div>)}</div> : <EmptyState title="No incidents yet" detail="Incidents recorded by your team will appear here." />}
          </article>
        </section>
        <section className="panel engine-panel"><div className="panel-heading"><div><p className="eyebrow">INTEGRATION LAYER</p><h3>Security engines</h3></div><button className="text-button" onClick={() => setView("integrations")}>Integration details <span>→</span></button></div><EngineCards wazuh={wazuh} wazuhManager={wazuhManager} crowdsec={crowdsec} canOperate={canOperate} refreshKey={refreshKey} /></section>
      </div>}

      {view !== "overview" && <div className="page-content">
        <SectionInsights view={view} assets={assets} findings={findings} incidents={incidents} />
        {view !== "detections" && view !== "threat-intel" && view !== "vulnerabilities" && view !== "playbooks" && view !== "assets" && view !== "findings" && view !== "incidents" && <section className="list-intro"><div><p className="eyebrow">OPERATIONAL DATA</p><h2>{view === "integrations" ? "Connected security engines" : pageTitle + " register"}</h2><p>{view === "integrations" ? "Connection state is read from the backend integration health endpoint." : view === "users" ? "Accounts and roles are loaded from the administrator-managed user API." : view === "reports" ? "Reports summarize authenticated operational records and collection history." : "Workspace preferences and access context are read from the active session."}</p></div></section>}
        {view === "settings" ? <section className="panel settings-workspace"><div className="panel-heading"><div><p className="eyebrow">ACCOUNT & PREFERENCES</p><h3>Workspace settings</h3></div></div><div className="settings-account-grid"><article><small>AUTHENTICATED ACCOUNT</small><strong>{user.email}</strong><span>Signed-in identity</span></article><article><small>ACCESS ROLE</small><strong>{titleCase(user.role)}</strong><span>Permissions are enforced by the API</span></article><article><small>APPEARANCE</small><strong>{titleCase(theme)} mode</strong><span>Preference saved in this browser</span><div className="settings-theme-actions"><button className="secondary-button" onClick={()=>setTheme("dark")}>Dark</button><button className="secondary-button" onClick={()=>setTheme("light")}>Light</button><button className="secondary-button" onClick={()=>setTheme("system")}>System</button></div></article></div><p className="integration-note">OpsAegis uses role-based access control. Account and permission changes must be performed through authorized administrator workflows; this page does not expose secret values or weaken server-side authorization.</p></section> : view === "reports" ? <><OperationsPanel isAdmin={user.role === "admin"} refreshKey={refreshKey} />{canOperate && <ExecutionLedgerPanel refreshKey={refreshKey} />}</> : view === "users" ? <AdminUsers currentUser={user} /> : view === "playbooks" ? <PlaybooksPanel incidents={incidents} user={user} /> : view === "vulnerabilities" ? <VulnerabilityPanel canOperate={canOperate} assets={assets} /> : view === "threat-intel" ? <ThreatIntelPanel canOperate={canOperate} /> : view === "detections" ? <DetectionsPanel canOperate={canOperate} isAdmin={user?.role === "admin"} /> : view === "integrations" ? <section className="panel integration-page"><div className="panel-heading"><div><p className="eyebrow">ADAPTER STATUS</p><h3>Engine connectivity</h3></div>{canOperate && <div className="header-actions"><button className="primary-button compact" onClick={handleCollect} disabled={collecting || !wazuh?.configured}>{collecting ? "Collecting Wazuh…" : "Collect Wazuh alerts"}</button><button className="primary-button compact" onClick={handleCollectCrowdSec} disabled={collectingCrowdSec || !crowdsec?.configured}>{collectingCrowdSec ? "Syncing CrowdSec…" : "Sync CrowdSec decisions"}</button><button className="secondary-button" onClick={handleWazuhManagerSync} disabled={syncingWazuhManager||!wazuhManager?.configured}>{syncingWazuhManager?"Syncing agents…":"Sync Manager agents"}</button></div>}</div><EngineCards wazuh={wazuh} wazuhManager={wazuhManager} crowdsec={crowdsec} canOperate={canOperate} refreshKey={refreshKey} /><CollectionPanel canOperate={canOperate} isAdmin={user.role === "admin"} /><NucleiPanel canOperate={canOperate} isAdmin={user.role === "admin"} assets={assets} /><ShannonPanel canOperate={canOperate} isAdmin={user.role === "admin"} /><p className="integration-note">Wazuh collection is read-only. CrowdSec imports active decisions only. Nuclei uses its fixed safe profile. Shannon dispatch requires a separately deployed isolated runner and written authorization.</p></section> :
          <section className="panel data-panel"><div className="panel-heading"><div><p className="eyebrow">DATABASE RECORDS</p><h3>{pageTitle}</h3></div></div><DataTable view={view} assets={assets} findings={findings} incidents={incidents} query={query} user={user} canOperate={canOperate} onFindingStatus={async (id, status) => { try { await updateFindingStatus(id, status); setRefreshKey((value) => value + 1); } catch (reason) { setCollectionError(reason instanceof Error ? reason.message : "Finding update failed."); } }} onIncidentUpdate={async (id, status, resolution, assignToMe) => { try { await updateIncident(id, {status, ...(assignToMe ? {assigned_to_user_id: user.id} : {}), resolution: resolution || undefined}); setRefreshKey((value) => value + 1); } catch (reason) { setCollectionError(reason instanceof Error ? reason.message : "Incident update failed."); } }} onIncidentCreated={() => setRefreshKey((value) => value + 1)} onAssetCreated={() => setRefreshKey((value) => value + 1)} /></section>}
      </div>}
      <footer className="app-footer"><span>OPSAEGIS · OPERATIONAL SECURITY & INCIDENT GOVERNANCE</span><span>API v1 <i /> SESSION AUTHENTICATED</span></footer>
  </AppDashboardShell>;
}

function EngineCards({ wazuh, wazuhManager, crowdsec, canOperate, refreshKey }: {
  wazuh: WazuhHealth | null; wazuhManager: WazuhManagerHealth | null; crowdsec: CrowdSecHealth | null;
  canOperate: boolean; refreshKey: number;
}) {
  const [nucleiHealth, setNucleiHealth] = useState<NucleiHealth | null>(null);
  const [shannonHealth, setShannonHealth] = useState<ShannonHealth | null>(null);
  const [nucleiHealthFailed, setNucleiHealthFailed] = useState(false);
  const [shannonHealthFailed, setShannonHealthFailed] = useState(false);

  useEffect(() => {
    if (!canOperate) {
      setNucleiHealth(null);
      setShannonHealth(null);
      setNucleiHealthFailed(false);
      setShannonHealthFailed(false);
      return;
    }
    let active = true;
    setNucleiHealth(null);
    setShannonHealth(null);
    setNucleiHealthFailed(false);
    setShannonHealthFailed(false);
    Promise.allSettled([getNucleiHealth(), getShannonHealth()]).then(([nuclei, shannon]) => {
      if (!active) return;
      if (nuclei.status === "fulfilled") setNucleiHealth(nuclei.value);
      else setNucleiHealthFailed(true);
      if (shannon.status === "fulfilled") setShannonHealth(shannon.value);
      else setShannonHealthFailed(true);
    });
    return () => { active = false; };
  }, [canOperate, refreshKey]);

  const nucleiPresentation = describeEngineHealth("Nuclei", nucleiHealth, canOperate, nucleiHealthFailed);
  const shannonPresentation = describeEngineHealth("Shannon", shannonHealth, canOperate, shannonHealthFailed);
  const engines = [
    { name: "Wazuh Manager API", role: "Registered endpoint inventory (read-only)", status: wazuhManager?.status || "unknown", detail: wazuhManager?.status === "healthy" ? "Authenticated Manager API reachable" : wazuhManager?.status === "unhealthy" ? "Manager API health check failed" : wazuhManager?.status === "not_configured" ? "Manager API credentials or URL not configured" : "Status unavailable" },
    { name: "Wazuh Indexer", role: "Read-only SIEM alert ingestion", status: wazuh?.status || "unknown", detail: wazuh?.status === "healthy" ? "Backend health check succeeded" : wazuh?.status === "unhealthy" ? "Backend could not reach the Indexer" : wazuh?.status === "not_configured" ? "Backend credentials or URL not configured" : "Status unavailable" },
    { name: "CrowdSec LAPI", role: "Active threat decisions (read-only)", status: crowdsec?.status || "unknown", detail: crowdsec?.status === "healthy" ? "Authenticated Local API health check succeeded" : crowdsec?.status === "unhealthy" ? "Backend could not authenticate or reach Local API" : crowdsec?.status === "not_configured" ? "Backend URL or bouncer key not configured" : "Status unavailable" },
    { name: "Nuclei", role: "Authorized vulnerability scanning", ...nucleiPresentation },
    { name: "Shannon", role: "Authorized application security testing", ...shannonPresentation },
  ];
  return <div className="engine-grid" aria-label="Security engine health">{engines.map((engine) => <article className="engine-card" key={engine.name}><div className="engine-card-top"><span className={"engine-indicator " + engine.status} aria-hidden="true" /><span className={"engine-status " + engine.status} role="status" aria-live="polite">{"label" in engine ? engine.label : titleCase(engine.status)}</span></div><h4>{engine.name}</h4><p>{engine.role}</p><small>{engine.detail}</small></article>)}</div>;
}

export default App;

function NucleiPanel({canOperate,isAdmin,assets}:{canOperate:boolean;isAdmin:boolean;assets:Asset[]}) {
 const [health,setHealth]=useState<NucleiHealth|null>(null),[targets,setTargets]=useState<NucleiTarget[]>([]),[scans,setScans]=useState<NucleiScan[]>([]);
 const [name,setName]=useState(""),[url,setUrl]=useState(""),[authorization,setAuthorization]=useState(""),[assetId,setAssetId]=useState("");
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
  try{await registerNucleiTarget({name:name.trim(),url:url.trim(),authorization_reference:authorization.trim(),asset_id:assetId?Number(assetId):null});setName("");setUrl("");setAuthorization("");setMessage("Authorized target registered.");await refresh();}
  catch(e){setError(e instanceof Error?e.message:"Target registration failed.");}finally{setBusy(false);}
 }
 async function scan(id:number){
  setBusy(true);setError("");setMessage("");
  try{const r=await startNucleiScan(id);setMessage(r.queued?"Scan #"+r.scan.id+" queued successfully. The isolated worker will update its status and findings as execution completes.":r.message||"Scan request accepted.");await refresh();}
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
   <label>Map scan results to asset (optional)<select value={assetId} onChange={e=>setAssetId(e.target.value)}><option value="">Unmapped — do not associate with an asset</option>{assets.map(asset=><option key={asset.id} value={asset.id}>{asset.name} · {asset.ip_address||"No IP"}</option>)}</select></label>
   <button className="primary-button compact" disabled={busy}>Register target</button>
  </form>}
  <div className="nuclei-target-list"><h4>Registered targets</h4>{targets.length?targets.map(t=><div className="nuclei-target-row" key={t.id}><div><strong>{t.name}</strong><small>{t.url} · {t.authorization_reference}</small></div><button className="primary-button compact" disabled={busy||!health?.execution_enabled||!t.enabled} onClick={()=>void scan(t.id)}>Run safe scan</button></div>):<EmptyState title="No authorized targets" detail="An administrator must register an approved HTTPS target before scanning."/>}</div>
  <div className="nuclei-target-list"><h4>Recent scan history</h4>{scans.length?scans.slice(0,10).map(s=><div className="nuclei-target-row" key={s.id}><div><strong>Scan #{s.id} · Target #{s.target_id}</strong><small>{s.status} · {s.findings_count} findings · {formatDate(s.created_at)}</small></div><span className="tag">{s.profile}</span></div>):<EmptyState title="No scans yet" detail="Scan execution history will appear here."/>}</div>
  {!health?.execution_enabled&&<p className="integration-note">Execution remains disabled until NUCLEI_ENABLED=true, NUCLEI_WORKER_ENABLED=true, and the isolated Nuclei worker is deployed, healthy and protected by an outbound target allowlist.</p>}
 </section>;
}
