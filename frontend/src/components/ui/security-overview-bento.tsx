"use client";

import { useEffect, useMemo, useState } from "react";
import type { Asset, Finding, Incident, OperationsReport, OperationsTrends } from "../api";
import { getOperationsReport, getOperationsTrends } from "../api";

type Props = { assets: Asset[]; findings: Finding[]; incidents: Incident[]; refreshKey: number };
const SEVERITIES = ["critical", "high", "medium", "low", "informational", "unknown"] as const;
const COLORS: Record<string, string> = {
  critical: "#ff5a5f", high: "#ff7a45", medium: "#ffb020",
  low: "#39c98a", informational: "#4da3ff", unknown: "#8792a2",
};
const number = (value: number) => Math.round(value).toLocaleString();
const dateLabel = (value: string) => new Date(value).toLocaleDateString(undefined, { month: "short", day: "numeric" });

function LineChart({ points }: { points: OperationsTrends["points"] }) {
  const width = 620, height = 156, pad = 12;
  const max = Math.max(1, ...points.map((p) => p.detections + p.incidents));
  const path = points.map((p, i) => {
    const x = pad + (i / Math.max(1, points.length - 1)) * (width - pad * 2);
    const y = height - pad - ((p.detections + p.incidents) / max) * (height - pad * 2);
    return (i ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1);
  }).join(" ");
  const area = path + ` L ${width - pad} ${height - pad} L ${pad} ${height - pad} Z`;
  return <div className="so-chart-wrap">
    {points.length ? <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Persisted detections and incidents over the selected 30-day window">
      <defs><linearGradient id="so-area" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#35d6a0" stopOpacity=".28"/><stop offset="1" stopColor="#35d6a0" stopOpacity="0"/></linearGradient></defs>
      {[.25,.5,.75].map((v)=><line key={v} x1="0" x2={width} y1={height*v} y2={height*v} className="so-gridline"/>)}
      <path d={area} fill="url(#so-area)"/><path d={path} fill="none" stroke="#35d6a0" strokeWidth="2.8" strokeLinecap="round" strokeLinejoin="round"/>
      {points.map((p,i)=>{const x=pad+(i/Math.max(1,points.length-1))*(width-pad*2);const y=height-pad-((p.detections+p.incidents)/max)*(height-pad*2);return <circle key={p.start} cx={x} cy={y} r="3" fill="#35d6a0"><title>{dateLabel(p.start)} · {p.detections} detections · {p.incidents} incidents</title></circle>;})}
    </svg> : <p className="so-empty">No persisted activity in this reporting window.</p>}
    <div className="so-axis"><span>{points[0] ? dateLabel(points[0].start) : "—"}</span><span>30-day activity</span><span>{points.length ? dateLabel(points[points.length-1].start) : "—"}</span></div>
  </div>;
}

function Donut({ counts, total }: { counts: Record<string, number>; total: number }) {
  let cursor = 0;
  const segments = SEVERITIES.map((key) => {
    const start = cursor; cursor += total ? (counts[key] / total) * 100 : 0;
    return `${COLORS[key]} ${start}% ${cursor}%`;
  }).join(", ");
  return <div className="so-donut" style={{ background: total ? `conic-gradient(${segments})` : "var(--line)" }}>
    <div><strong>{number(total)}</strong><small>findings</small></div>
  </div>;
}

export function SecurityOverviewBento({ assets, findings, incidents, refreshKey }: Props) {
  const [trends, setTrends] = useState<OperationsTrends | null>(null);
  const [report, setReport] = useState<OperationsReport | null>(null);
  const [trendError, setTrendError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    const until = new Date();
    const since = new Date(until.getTime() - 30 * 86400000);
    setLoading(true);
    Promise.all([getOperationsTrends(since.toISOString(), until.toISOString(), "day"), getOperationsReport(since.toISOString(), until.toISOString())])
      .then(([t, r]) => { if (active) { setTrends(t); setReport(r); setTrendError(""); } })
      .catch((error: unknown) => { if (active) setTrendError(error instanceof Error ? error.message : "Operational analytics are unavailable."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [refreshKey]);

  const severityCounts = useMemo(() => Object.fromEntries(SEVERITIES.map((key) => [key, findings.filter((item) => item.severity === key).length])) as Record<string, number>, [findings]);
  const sourceCounts = useMemo(() => {
    const counts = new Map<string, number>();
    findings.forEach((item) => counts.set(item.source_engine || "unknown", (counts.get(item.source_engine || "unknown") || 0) + 1));
    return [...counts.entries()].sort((a,b)=>b[1]-a[1]).slice(0,6);
  }, [findings]);
  const totals = useMemo(() => (trends?.points ?? []).reduce((acc,p) => ({
    detections: acc.detections + p.detections, incidents: acc.incidents + p.incidents,
    runs: acc.runs + p.collection_runs, succeeded: acc.succeeded + p.collection_succeeded, failed: acc.failed + p.collection_failed,
    resolved: acc.resolved + p.resolved_incidents,
  }), {detections:0,incidents:0,runs:0,succeeded:0,failed:0,resolved:0}), [trends]);
  const activeIncidents = incidents.filter((item) => ["open","investigating","contained"].includes(item.status)).length;
  const openFindings = findings.filter((item) => ["new","triaged"].includes(item.status)).length;
  const sourceRows = report?.collection.sources ?? [];
  const weekday = useMemo(() => {
    const counts = Array(7).fill(0) as number[];
    (trends?.points ?? []).forEach((p) => { counts[new Date(p.start).getUTCDay()] += p.detections + p.incidents; });
    return counts;
  }, [trends]);
  const maxWeekday = Math.max(1, ...weekday);
  const radarPoints = weekday.map((v,i) => {
    const angle = -Math.PI/2 + i/7*Math.PI*2, radius = 30 + (v/maxWeekday)*72;
    return [100+Math.cos(angle)*radius,100+Math.sin(angle)*radius] as [number,number];
  });
  const radarPath = radarPoints.map(([x,y],i)=>(i?"L":"M")+x.toFixed(1)+" "+y.toFixed(1)).join(" ")+" Z";

  return <section className="security-overview" aria-label="Security analytics overview">
    <div className="so-top-grid">
      <article className="so-card so-kpi">
        <div className="so-card-heading"><span>SECURITY EVENTS</span><i className="so-live-dot"/></div>
        <div className="so-kpi-row"><strong>{number(totals.detections + totals.incidents)}</strong><span>30 DAYS</span></div>
        <p>Persisted detections and incidents · UTC</p>
        <LineChart points={trends?.points ?? []}/>
      </article>
      <article className="so-card so-kpi">
        <div className="so-card-heading"><span>COLLECTION ACTIVITY</span><span className="so-muted">30-DAY WINDOW</span></div>
        <div className="so-kpi-row"><strong>{number(totals.runs)}</strong><span className="so-status">{totals.runs ? Math.round(totals.succeeded/totals.runs*100) + "% succeeded" : "No runs"}</span></div>
        <p>{number(totals.succeeded)} successful · {number(totals.failed)} failed collection runs</p>
        <div className="so-collection-bars" aria-label="Successful and failed collection runs">
          {(trends?.points ?? []).map((p)=><div key={p.start} title={`${dateLabel(p.start)}: ${p.collection_succeeded} successful, ${p.collection_failed} failed`}><i style={{height:Math.max(3,p.collection_succeeded/Math.max(1,totals.runs)*100)+"%"}}/><b style={{height:Math.max(2,p.collection_failed/Math.max(1,totals.runs)*100)+"%"}}/></div>)}
        </div>
        <div className="so-legend"><span><i className="success"/>Successful</span><span><i className="failure"/>Failed</span></div>
      </article>
    </div>

    <div className="so-main-grid">
      <article className="so-card so-severity">
        <div className="so-section-heading"><div><small>FINDINGS LANDSCAPE</small><h3>Findings by severity</h3></div><span className="so-muted">{findings.length} records · API limit 200</span></div>
        <div className="so-severity-layout">
          <Donut counts={severityCounts} total={findings.length}/>
          <div className="so-severity-legend">{SEVERITIES.filter((key)=>severityCounts[key]>0).map((key)=><div key={key}><i style={{background:COLORS[key]}}/><span>{key.charAt(0).toUpperCase()+key.slice(1)}</span><strong>{number(severityCounts[key])}</strong><small>{findings.length?Math.round(severityCounts[key]/findings.length*100):0}%</small></div>)}
            {!findings.length && <p className="so-empty">No findings returned by the API.</p>}
          </div>
        </div>
        <div className="so-source-heading"><span>FINDINGS BY SOURCE</span><span>RECORDS</span></div>
        {sourceCounts.length ? sourceCounts.map(([name,count])=><div className="so-source-row" key={name}><span>{name.replace(/_/g," ")}</span><div><i style={{width:(count/Math.max(1,sourceCounts[0][1])*100)+"%"}}/></div><strong>{count}</strong></div>) : <p className="so-empty">No source distribution available.</p>}
      </article>

      <article className="so-card so-response">
        <div className="so-section-heading"><div><small>RESPONSE RHYTHM</small><h3>Activity by weekday</h3></div><span className="so-muted">30 days · UTC</span></div>
        <div className="so-radar-wrap"><svg viewBox="0 0 200 200" role="img" aria-label="Detections and incidents distributed by weekday">
          {[30,66,102].map((r)=><circle key={r} cx="100" cy="100" r={r} className="so-radar-grid"/>)}{Array.from({length:7},(_,i)=>{const a=-Math.PI/2+i/7*Math.PI*2;return <line key={i} x1={100+Math.cos(a)*30} y1={100+Math.sin(a)*30} x2={100+Math.cos(a)*102} y2={100+Math.sin(a)*102} className="so-radar-grid"/>})}
          <path d={radarPath} fill="#35d6a0" fillOpacity=".12" stroke="#35d6a0" strokeWidth="2.2"/>
        </svg></div>
        <div className="so-weekday-grid">{["Sun","Mon","Tue","Wed","Thu","Fri","Sat"].map((day,i)=><div key={day}><span>{day}</span><strong>{number(weekday[i])}</strong></div>)}</div>
        <div className="so-response-stats"><div><small>ACTIVE INCIDENTS</small><strong>{number(activeIncidents)}</strong></div><div><small>RESOLVED IN WINDOW</small><strong>{number(totals.resolved)}</strong></div><div><small>NEW / TRIAGED FINDINGS</small><strong>{number(openFindings)}</strong></div></div>
      </article>
    </div>

    <article className="so-card so-sources">
      <div className="so-section-heading"><div><small>INTEGRATION HEALTH</small><h3>Data sources & freshness</h3></div><span className="so-muted">{sourceRows.length} configured sources</span></div>
      {loading && <p className="so-empty">Loading persisted operational metrics…</p>}
      {trendError && <p className="so-error" role="alert">{trendError}</p>}
      {!loading && sourceRows.length>0 && <div className="so-source-health-grid">{sourceRows.map((source)=><div key={source.source}><i className={source.freshness}/><span>{source.source}</span><strong>{source.freshness.replace("_"," ")}</strong><small>{source.successful_runs} / {source.runs} successful</small></div>)}</div>}
      {!loading && !sourceRows.length && !trendError && <p className="so-empty">No configured collection sources were reported for this window.</p>}
      {trends?.rows_limited && <p className="so-warning">The reporting query reached its row safety cap; trend totals may be incomplete.</p>}
      <p className="so-footnote">All charts use authenticated, persisted OpsAegis records. Empty states are shown when no records exist; this view does not generate sample telemetry.</p>
    </article>
  </section>;
}
