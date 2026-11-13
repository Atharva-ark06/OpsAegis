import { useEffect, useState } from "react";
import { AnalyticsBento } from "./analytics-bento";
import type { Asset, Finding, Incident, OperationsReport, OperationsTrends } from "../../api";
import { getOperationsReport, getOperationsTrends } from "../../api";

type Props = { assets: Asset[]; findings: Finding[]; incidents: Incident[]; refreshKey: number };
const severityColors = [
  { id: "critical", name: "Critical", color: "#ff5a5f", ink: "light" as const },
  { id: "high", name: "High", color: "#ff7a45", ink: "light" as const },
  { id: "medium", name: "Medium", color: "#ffb800", ink: "dark" as const },
  { id: "low", name: "Low", color: "#7cff5b", ink: "dark" as const },
  { id: "informational", name: "Informational", color: "#8b3dff", ink: "light" as const },
  { id: "unknown", name: "Unknown", color: "#6b7280", ink: "light" as const },
];
const dateLabel = (value: string) => new Date(value).toLocaleDateString("en-US", { month: "short", day: "numeric" });
const sum = (values: number[]) => values.reduce((a, b) => a + b, 0);
const dailyZeroSeries = (since: Date, until: Date) => [{ label: dateLabel(since.toISOString()), value: 0 }, { label: dateLabel(until.toISOString()), value: 0 }];

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

  const points = trends?.points ?? [];
  const dailyEvents = points.map((p) => ({ label: dateLabel(p.start), value: p.detections + p.incidents }));
  const successSeries = points.map((p) => p.collection_succeeded);
  const failureSeries = points.map((p) => p.collection_failed);
  const eventTotal = sum(dailyEvents.map((p) => p.value));
  const openFindings = findings.filter((f) => ["new", "triaged"].includes(f.status)).length;
  const activeIncidents = incidents.filter((i) => ["open", "investigating", "contained"].includes(i.status)).length;
  const weeklyFindings = findings.filter((f) => Date.now() - new Date(f.first_seen_at).getTime() <= 7 * 86400000).length;
  const sourceCounts = new Map<string, number>();
  findings.forEach((f) => sourceCounts.set(f.source_engine || "unknown", (sourceCounts.get(f.source_engine || "unknown") ?? 0) + 1));
  const topSources = [...sourceCounts.entries()].sort((a,b)=>b[1]-a[1]).slice(0,3);
  const weekday = Array(7).fill(0) as number[];
  points.forEach((p) => { weekday[new Date(p.start).getUTCDay()] += p.detections + p.incidents; });
  const sourceRows = report?.collection.sources ?? [];
  const activitySeries = dailyEvents.length >= 2 ? dailyEvents : dailyZeroSeries(new Date(Date.now()-86400000), new Date());
  const collectionSuccess = successSeries.length >= 2 ? successSeries : [0, 0];
  const collectionFailure = failureSeries.length >= 2 ? failureSeries : [0, 0];
  const sessionsCount = sum(collectionSuccess) + sum(collectionFailure);
  const trendNote = loading ? "Loading persisted telemetry…" : trends?.rows_limited ? "API result reached its row safety cap" : "Persisted events · UTC";
  const years = [{ label: "30 days", values: weekday, stats: [
    { label: "Active incidents", value: activeIncidents, delta: "LIVE", note: "current records" },
    { label: "Open findings", value: openFindings, delta: "LIVE", note: "new + triaged" },
  ], rows: topSources.map(([label,value])=>({label,value:value.toLocaleString()})) }];
  const groups = severityColors;
  const totals = [
    { label: "7 days", total: weeklyFindings, delta: "API", compare: "Findings first seen in last 7 days" },
    { label: "30 days", total: findings.filter((f)=>Date.now()-new Date(f.first_seen_at).getTime()<=30*86400000).length, delta: "API", compare: "Findings first seen in last 30 days" },
    { label: "Loaded", total: findings.length, delta: "API", compare: "Records returned by authenticated API" },
  ];
  const items = findings.map((f)=>({name:f.title,group:f.severity||"unknown",values:[Date.now()-new Date(f.first_seen_at).getTime()<=7*86400000?1:0,Date.now()-new Date(f.first_seen_at).getTime()<=30*86400000?1:0,1]}));
  return <div className="aegis-analytics-stage">
    <div className="aegis-analytics-meta"><span><i/> SECURITY OPERATIONS · LIVE API DATA</span><span>{loading?"SYNCING":error?"DEGRADED":"30-DAY WINDOW"}{trends?.rows_limited?" · ROW LIMIT REACHED":""}</span></div>
    {error && <div className="aegis-analytics-error" role="alert">{error}</div>}
    <AnalyticsBento
      className="mx-auto max-w-[1240px]"
      currency=""
      fontFamily="Inter, ui-sans-serif, system-ui, sans-serif"
      monoFamily="'Geist Mono', ui-monospace, SFMono-Regular, monospace"
      credit={false}
      revenue={{label:"Security events",value:eventTotal,delta:"30D",note:"Persisted detections + incidents",caption:"Daily activity · last 30 days",series:activitySeries}}
      sessions={{label:"Collection runs",value:sessionsCount,delta:"30D",note:trendNote,desktop:[collectionSuccess],mobile:[collectionFailure],labels:{desktop:"Successful",mobile:"Failed",prior:"",current:"daily collection"}}}
      categories={{title:"Findings by severity",groups,periods:totals,items,table:{columns:["Source engine","Findings"],rows:topSources.map(([label,value])=>({label,values:[value.toLocaleString()]}))}}}
      seasonality={{title:"Response rhythm",axis:["Sun","Mon","Tue","Wed","Thu","Fri","Sat"],years}}
      colors={{revenue:["#22d3ee","#3bf08c"],desktop:["#22d3ee","#3c2cff"],mobile:["#ffb800","#ff3da5"],radar:"#3bf08c"}}
    />
    <div className="aegis-analytics-footnote">Charts and counts are derived from authenticated OpsAegis records. Collection sources configured: {report?.collection.sources_configured ?? 0} · Monitored assets: {assets.length} · Finding records loaded: {findings.length} · Incident records loaded: {incidents.length}. {trends?.limitations?.join(" ") || ""}</div>
  </div>;
}
