import { useEffect, useMemo, useState } from "react";
import type { Asset, Finding, Incident, OperationsReport, OperationsTrends } from "../../api";
import { getOperationsReport, getOperationsTrends } from "../../api";

type Props = { assets: Asset[]; findings: Finding[]; incidents: Incident[]; refreshKey: number };
const severities = ["critical", "high", "medium", "low", "informational", "unknown"];
const label = (value: string) => value.replace(/_/g, " ").replace(/\\b\\w/g, (letter) => letter.toUpperCase());
const formatDay = (value: string) => new Date(value).toLocaleDateString(undefined, { month: "short", day: "numeric" });
function Metric({ title, value, detail, tone }: { title: string; value: number; detail: string; tone: string }) {
  return <article className={"overview-command-metric " + tone}><span>{title}</span><strong>{value.toLocaleString()}</strong><small>{detail}</small></article>;
}
function Distribution({ title, values, total }: { title: string; values: [string, number][]; total: number }) {
  return <section className="overview-command-card">
    <div className="overview-command-card-head"><h3>{title}</h3><span>{total.toLocaleString()} records</span></div>
    {values.map(([name, value]) => <div className="overview-distribution-row" key={name}>
      <div><span><i className={"overview-severity-dot " + name} />{label(name)}</span><b>{value}</b></div>
      <div className="overview-track"><i className={name} style={{ width: (total ? value / total * 100 : 0) + "%" }} /></div>
    </div>)}
    {!values.length && <p className="overview-empty">No records available from the API.</p>}
  </section>;
}
export function SecurityOverviewBento({ assets, findings, incidents, refreshKey }: Props) {
  const [trends, setTrends] = useState<OperationsTrends | null>(null);
  const [report, setReport] = useState<OperationsReport | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    const until = new Date();
    const since = new Date(until.getTime() - 30 * 86400000);
    setLoading(true);
    Promise.all([
      getOperationsTrends(since.toISOString(), until.toISOString(), "day"),
      getOperationsReport(since.toISOString(), until.toISOString()),
    ]).then(([trendData, reportData]) => {
      if (active) { setTrends(trendData); setReport(reportData); setError(""); }
    }).catch((reason: unknown) => {
      if (active) setError(reason instanceof Error ? reason.message : "Security analytics could not be loaded.");
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [refreshKey]);

  const severityRows = useMemo(() => severities.map((severity) =>
    [severity, findings.filter((item) => item.severity === severity).length] as [string, number]
  ).filter((row) => row[1] > 0), [findings]);
  const statusRows = useMemo(() => ["new", "triaged", "accepted", "false_positive", "resolved"].map((status) =>
    [status, findings.filter((item) => item.status === status).length] as [string, number]
  ).filter((row) => row[1] > 0), [findings]);
  const activeIncidents = incidents.filter((item) => ["open", "investigating", "contained"].includes(item.status));
  const linkedAssetCounts = assets.map((asset) => ({
    asset,
    count: findings.filter((finding) => finding.asset_id === asset.id && ["new", "triaged", "accepted"].includes(finding.status)).length,
  })).filter((row) => row.count > 0).sort((a,b) => b.count-a.count).slice(0,5);
  const points = (trends?.points ?? []).slice(-14);
  const maxActivity = Math.max(1, ...points.map((point) => point.detections + point.incidents));
  const sourcesConfigured = report?.collection.sources_configured ?? 0;
  const collectionState = loading ? "Syncing operational metrics…" : error ? "Analytics unavailable" : "Authenticated operational data";
  return <section className="overview-command">
    <div className="overview-command-heading"><div><small>SECURITY OPERATIONS · COMMAND CENTER</small><h2>Security posture at a glance</h2><p>One operational view across assets, findings, incidents and collection configuration.</p></div><span className="overview-command-state"><i />{collectionState}</span></div>
    {error && <div className="error-banner" role="alert">{error}</div>}
    <div className="overview-command-metrics">
      <Metric title="Assets monitored" value={assets.length} detail="Registered asset records" tone="blue" />
      <Metric title="Critical findings" value={findings.filter((item) => item.severity === "critical" && item.status !== "resolved").length} detail="Unresolved critical severity" tone="red" />
      <Metric title="Active incidents" value={activeIncidents.length} detail="Open · investigating · contained" tone="orange" />
      <Metric title="Sources configured" value={sourcesConfigured} detail="Reported by operations API" tone="green" />
    </div>
    <div className="overview-command-grid">
      <Distribution title="Alert distribution" values={severityRows} total={findings.length} />
      <Distribution title="Remediation status" values={statusRows} total={findings.length} />
      <section className="overview-command-card overview-activity-card">
        <div className="overview-command-card-head"><h3>Security activity</h3><span>Last 14 available days</span></div>
        {points.length ? <div className="overview-activity-bars">{points.map((point) => {
          const count = point.detections + point.incidents;
          return <div key={point.start} title={formatDay(point.start) + ": " + count + " events"}>
            <i style={{ height: Math.max(3, count / maxActivity * 100) + "%" }} />
            <small>{new Date(point.start).toLocaleDateString(undefined, { day: "numeric" })}</small>
          </div>;
        })}</div> : <p className="overview-empty">{loading ? "Loading activity…" : "No persisted activity points were returned for this period."}</p>}
        <div className="overview-activity-legend"><span><i className="detections" />Detections</span><span><i className="incidents" />Incidents</span></div>
      </section>
      <section className="overview-command-card overview-asset-risk-card">
        <div className="overview-command-card-head"><h3>Assets with linked open findings</h3><span>{linkedAssetCounts.length} shown</span></div>
        {linkedAssetCounts.length ? linkedAssetCounts.map(({asset,count}) => <div className="overview-asset-risk-row" key={asset.id}>
          <div><strong>{asset.name}</strong><small>{label(asset.asset_type)} · {label(asset.environment || "unknown")}</small></div><b>{count}</b>
        </div>) : <p className="overview-empty">No assets currently have linked open findings.</p>}
      </section>
    </div>
    <p className="overview-command-footnote">Counts are derived from authenticated OpsAegis records. No synthetic risk score, MITRE mapping, mean response time or provider health is inferred when the backend does not supply it.</p>
  </section>;
}
