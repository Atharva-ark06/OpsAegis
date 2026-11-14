import type { Asset, Finding, Incident } from "../../api";

type Props = { view: string; assets: Asset[]; findings: Finding[]; incidents: Incident[] };
const label = (value: string) => value.replace(/_/g, " ").replace(/\\b\\w/g, (letter) => letter.toUpperCase());
const activeFinding = (item: Finding) => ["new", "triaged", "accepted"].includes(item.status);
const activeIncident = (item: Incident) => ["open", "investigating", "contained"].includes(item.status);
const dateLabel = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Date unavailable" : date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
};
function Metric({ label: title, value, note, tone = "blue" }: { label: string; value: number; note: string; tone?: string }) {
  return <article className={"section-metric tone-" + tone}><span>{title}</span><strong>{value.toLocaleString()}</strong><small>{note}</small></article>;
}
function BarList({ title, rows }: { title: string; rows: [string, number][] }) {
  const max = Math.max(1, ...rows.map((row) => row[1]));
  return <section className="section-chart-card">
    <div className="section-card-heading"><h3>{title}</h3><span>{rows.reduce((sum, row) => sum + row[1], 0)} total</span></div>
    {rows.length ? <div className="section-bars">{rows.map(([name, value]) => <div className="section-bar-row" key={name}>
      <div><span>{label(name)}</span><strong>{value}</strong></div>
      <i><b style={{ width: (value / max * 100) + "%" }} /></i>
    </div>)}</div> : <p className="section-empty-note">No records returned by the API.</p>}
  </section>;
}
export function SectionInsights({ view, assets, findings, incidents }: Props) {
  if (view === "assets") {
    const exposed = assets.filter((asset) => findings.some((finding) => finding.asset_id === asset.id && activeFinding(finding)));
    const byType = new Map<string, number>();
    const byEnvironment = new Map<string, number>();
    assets.forEach((asset) => {
      byType.set(asset.asset_type || "unknown", (byType.get(asset.asset_type || "unknown") || 0) + 1);
      byEnvironment.set(asset.environment || "unknown", (byEnvironment.get(asset.environment || "unknown") || 0) + 1);
    });
    const assetRows = assets.slice(0, 6).map((asset) => ({
      ...asset,
      linked: findings.filter((finding) => finding.asset_id === asset.id && activeFinding(finding)).length,
    }));
    return <section className="section-workspace section-assets">
      <div className="section-workspace-heading"><div><small>ATTACK SURFACE · INVENTORY INTELLIGENCE</small><h2>Know what is exposed.</h2><p>Asset inventory and linked open findings from the authenticated OpsAegis APIs.</p></div><span className="section-live-label">API INVENTORY</span></div>
      <div className="section-metric-grid">
        <Metric label="Registered assets" value={assets.length} note="Records returned" />
        <Metric label="Assets with open findings" value={exposed.length} note="Linked by asset ID" tone="orange" />
        <Metric label="Production assets" value={assets.filter((asset) => asset.environment === "production").length} note="Environment metadata" tone="purple" />
        <Metric label="Agent status reported" value={assets.filter((asset) => Boolean(asset.agent_status)).length} note="Status supplied by source" tone="green" />
      </div>
      <div className="section-two-column">
        <BarList title="Inventory by environment" rows={[...byEnvironment.entries()].sort((a,b)=>b[1]-a[1])} />
        <BarList title="Asset classes" rows={[...byType.entries()].sort((a,b)=>b[1]-a[1])} />
      </div>
      <section className="section-chart-card section-asset-preview">
        <div className="section-card-heading"><h3>Assets requiring attention</h3><span>Top 6 · linked open findings</span></div>
        {assetRows.length ? <div className="section-asset-list">{assetRows.sort((a,b)=>b.linked-a.linked).map((asset) => <article key={asset.id}>
          <span className="section-asset-symbol">{label(asset.asset_type).slice(0,2).toUpperCase()}</span>
          <div><strong>{asset.name}</strong><small>{label(asset.asset_type)} · {label(asset.environment || "unknown")} · {asset.ip_address || "No IP reported"}</small></div>
          <span className={asset.linked ? "section-count-alert" : "section-count-neutral"}>{asset.linked} open</span>
        </article>)}</div> : <p className="section-empty-note">No assets have been registered yet.</p>}
      </section>
    </section>;
  }
  if (view === "findings") {
    const severityOrder = ["critical", "high", "medium", "low", "informational", "unknown"];
    const severityCounts = severityOrder.map((severity) => [severity, findings.filter((item) => item.severity === severity).length] as [string, number]).filter((row) => row[1] > 0);
    const statusCounts = ["new", "triaged", "accepted", "false_positive", "resolved"].map((status) => [status, findings.filter((item) => item.status === status).length] as [string, number]).filter((row) => row[1] > 0);
    const sourceCounts = new Map<string, number>();
    findings.forEach((item) => sourceCounts.set(item.source_engine || "unknown", (sourceCounts.get(item.source_engine || "unknown") || 0) + 1));
    const queue = [...findings].sort((a,b) => {
      const rank = (value: string) => severityOrder.indexOf(value);
      return rank(a.severity) - rank(b.severity) || new Date(b.last_seen_at).getTime() - new Date(a.last_seen_at).getTime();
    }).slice(0, 7);
    return <section className="section-workspace section-findings">
      <div className="section-workspace-heading"><div><small>SECURITY ISSUE REGISTER · TRIAGE QUEUE</small><h2>Prioritise what needs fixing.</h2><p>Findings are broader security issues. CVE-specific exploitability is managed in Vulnerabilities.</p></div><span className="section-live-label">NORMALIZED FINDINGS</span></div>
      <div className="section-metric-grid">
        <Metric label="Total findings" value={findings.length} note="Authenticated API records" />
        <Metric label="Critical / high" value={findings.filter((item) => ["critical", "high"].includes(item.severity)).length} note="Severity classification" tone="red" />
        <Metric label="Open / triage" value={findings.filter((item) => ["new", "triaged"].includes(item.status)).length} note="Awaiting analyst workflow" tone="orange" />
        <Metric label="Resolved" value={findings.filter((item) => item.status === "resolved").length} note="Marked resolved" tone="green" />
      </div>
      <div className="section-two-column">
        <BarList title="Severity distribution" rows={severityCounts} />
        <BarList title="Workflow status" rows={statusCounts} />
      </div>
      <section className="section-chart-card">
        <div className="section-card-heading"><h3>Prioritised findings</h3><span>Highest severity first · latest activity</span></div>
        {queue.length ? <div className="section-finding-list">{queue.map((item) => <article key={item.id}>
          <div className={"section-severity-mark severity-" + item.severity} />
          <div className="section-finding-main"><strong>{item.title}</strong><small>{label(item.source_engine)} · {item.asset_id ? "Asset #" + item.asset_id : "Asset not linked"} · Last seen {dateLabel(item.last_seen_at)}</small></div>
          <span className={"severity severity-" + item.severity}>{label(item.severity)}</span>
          <span className="section-status-label">{label(item.status)}</span>
        </article>)}</div> : <p className="section-empty-note">No findings have been recorded.</p>}
        <div className="section-source-foot"><span>Sources represented</span>{[...sourceCounts.entries()].sort((a,b)=>b[1]-a[1]).slice(0,4).map(([source,count])=><span key={source}>{label(source)} <b>{count}</b></span>)}</div>
      </section>
    </section>;
  }
  if (view === "incidents") {
    const active = incidents.filter(activeIncident);
    const critical = incidents.filter((item) => item.severity === "critical" && activeIncident(item));
    const statusCounts = ["open", "investigating", "contained", "resolved", "closed"].map((status) => [status, incidents.filter((item) => item.status === status).length] as [string, number]).filter((row) => row[1] > 0);
    const severityCounts = ["critical", "high", "medium", "low"].map((severity) => [severity, incidents.filter((item) => item.severity === severity).length] as [string, number]).filter((row) => row[1] > 0);
    const latest = [...incidents].sort((a,b)=>new Date(b.created_at).getTime()-new Date(a.created_at).getTime()).slice(0,6);
    return <section className="section-workspace section-incidents">
      <div className="section-workspace-heading"><div><small>INCIDENT COMMAND · INVESTIGATION LIFECYCLE</small><h2>Investigate. Contain. Resolve.</h2><p>Incident cases are separate from raw detections and retain their own ownership, notes and response state.</p></div><span className="section-live-label">CASE REGISTER</span></div>
      <div className="section-metric-grid">
        <Metric label="Active cases" value={active.length} note="Open, investigating, contained" tone="orange" />
        <Metric label="Critical active" value={critical.length} note="Requires immediate review" tone="red" />
        <Metric label="Resolved / closed" value={incidents.filter((item) => ["resolved", "closed"].includes(item.status)).length} note="Completed cases" tone="green" />
        <Metric label="All incidents" value={incidents.length} note="Authenticated API records" />
      </div>
      <div className="section-two-column section-incident-columns">
        <BarList title="Incident lifecycle" rows={statusCounts} />
        <BarList title="Severity profile" rows={severityCounts} />
      </div>
      <section className="section-chart-card section-incident-timeline">
        <div className="section-card-heading"><h3>Investigation activity</h3><span>Newest cases first</span></div>
        {latest.length ? <div className="section-timeline">{latest.map((item) => <article key={item.id}>
          <span className={"section-timeline-dot severity-" + item.severity} />
          <div><strong>{item.title}</strong><small>{dateLabel(item.created_at)} · {label(item.status)} · {label(item.severity)}</small></div>
          <span className="section-status-label">{item.id ? "INC-" + item.id : "Incident"}</span>
        </article>)}</div> : <p className="section-empty-note">No incident cases have been created.</p>}
      </section>
    </section>;
  }
  return null;
}
