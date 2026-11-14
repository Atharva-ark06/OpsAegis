import { useEffect, useMemo, useState } from "react";
import type { Asset, Finding, Incident, OverviewActivity } from "../../api";
import { getOverviewActivity } from "../../api";

type Props = { assets: Asset[]; findings: Finding[]; incidents: Incident[]; refreshKey: number };
type Period = 7 | 30 | 365;
const SECTIONS = [
  { id: "assets", label: "Assets", color: "var(--ov-violet)" },
  { id: "findings", label: "Findings", color: "var(--ov-blue)" },
  { id: "vulnerabilities", label: "Vulnerabilities", color: "var(--ov-orange)" },
  { id: "detections", label: "Detections", color: "var(--ov-cyan)" },
  { id: "incidents", label: "Incidents", color: "var(--ov-red)" },
  { id: "integrations", label: "Integrations", color: "var(--ov-green)" },
  { id: "threat-intel", label: "Threat Intel", color: "var(--ov-lime)" },
  { id: "playbooks", label: "Playbooks", color: "var(--ov-purple)" },
  { id: "users", label: "Users & Roles", color: "var(--ov-pink)" },
  { id: "reports", label: "Reports", color: "var(--ov-yellow)" },
  { id: "settings", label: "Settings", color: "var(--ov-slate)" },
] as const;
const fmt = (n: number) => n.toLocaleString();
const title = (value: string) => value.replace(/[-_.]/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
const dateLabel = (value: string) => new Date(value).toLocaleDateString(undefined, { month: "short", day: "numeric" });
const clockLabel = (value: string) => new Date(value).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
const sum = (items: number[]) => items.reduce((total, value) => total + value, 0);

function pathFor(values: number[], width: number, height: number, max: number) {
  if (!values.length) return "";
  return values.map((value, index) => {
    const x = values.length === 1 ? width / 2 : index * width / (values.length - 1);
    const y = height - (value / Math.max(1, max)) * (height - 8) - 4;
    return (index === 0 ? "M" : "L") + x.toFixed(1) + " " + y.toFixed(1);
  }).join(" ");
}

function Sparkline({ values, color = "var(--ov-cyan)" }: { values: number[]; color?: string }) {
  const max = Math.max(1, ...values);
  const path = pathFor(values, 440, 90, max);
  const area = path ? path + " L440 90 L0 90 Z" : "";
  return <svg className="ov-sparkline" viewBox="0 0 440 90" preserveAspectRatio="none" role="img" aria-label="Activity trend">
    <defs><linearGradient id="ov-spark-fill" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stopColor={color} stopOpacity=".24"/><stop offset="1" stopColor={color} stopOpacity="0"/></linearGradient></defs>
    {[22, 45, 68].map(y => <line key={y} x1="0" x2="440" y1={y} y2={y} className="ov-chart-gridline" />)}
    {area && <path d={area} fill="url(#ov-spark-fill)" />}
    {path && <path d={path} fill="none" stroke={color} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" vectorEffect="non-scaling-stroke"/>}
  </svg>;
}

function MultiLineChart({ data }: { data: OverviewActivity["daily"] }) {
  const series = ["threat-intel", "detections", "incidents", "findings"];
  const colors = ["var(--ov-lime)", "var(--ov-cyan)", "var(--ov-red)", "var(--ov-violet)"];
  const points = data.slice(-30);
  const max = Math.max(1, ...points.flatMap(point => series.map(key => point.by_section[key] ?? 0)));
  return <div className="ov-lines-wrap">
    <svg className="ov-lines-chart" viewBox="0 0 600 150" preserveAspectRatio="none" role="img" aria-label="Daily activity by security section over the last 30 days">
      {[30, 65, 100, 135].map(y => <line key={y} x1="0" x2="600" y1={y} y2={y} className="ov-chart-gridline" />)}
      {series.map((key, index) => <path key={key} d={pathFor(points.map(point => point.by_section[key] ?? 0), 600, 140, max)} fill="none" stroke={colors[index]} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" vectorEffect="non-scaling-stroke"/>)}
    </svg>
    <div className="ov-chart-legend">{series.map((key, index) => <span key={key}><i style={{ background: colors[index] }}/>{title(key)}</span>)}</div>
  </div>;
}

function RadarChart({ monthly }: { monthly: OverviewActivity["monthly"] }) {
  const values = monthly.map(item => item.total);
  const max = Math.max(1, ...values);
  const center = 150;
  const radius = 112;
  const coords = values.map((value, index) => {
    const angle = (Math.PI * 2 * index / 12) - Math.PI / 2;
    const r = 22 + (value / max) * (radius - 22);
    return [center + Math.cos(angle) * r, center + Math.sin(angle) * r] as const;
  });
  const polygon = coords.map(([x,y]) => x.toFixed(1) + "," + y.toFixed(1)).join(" ");
  return <svg className="ov-radar" viewBox="0 0 300 300" role="img" aria-label="Monthly security activity pattern for the last 12 months">
    {[28, 56, 84, 112].map(r => <circle key={r} cx={center} cy={center} r={r} className="ov-radar-ring" />)}
    {monthly.map((item,index) => {
      const angle = (Math.PI * 2 * index / 12) - Math.PI / 2;
      const x = center + Math.cos(angle) * radius;
      const y = center + Math.sin(angle) * radius;
      return <g key={item.month}><line x1={center} y1={center} x2={x} y2={y} className="ov-radar-axis"/><text x={center + Math.cos(angle) * 132} y={center + Math.sin(angle) * 132 + 3} className="ov-radar-label" textAnchor="middle">{item.label}</text></g>;
    })}
    {polygon && <polygon points={polygon} className="ov-radar-area"/>}
    {coords.map(([x,y],index) => <circle key={index} cx={x} cy={y} r="3" className="ov-radar-point"/>)}
    <circle cx={center} cy={center} r="14" className="ov-radar-core"/>
  </svg>;
}

function PanelHead({ eyebrow, heading, trailing }: { eyebrow?: string; heading: string; trailing?: React.ReactNode }) {
  return <div className="ov-panel-head"><div>{eyebrow && <small>{eyebrow}</small>}<h3>{heading}</h3></div>{trailing}</div>;
}

export function SecurityOverviewBento({ assets, findings, incidents, refreshKey }: Props) {
  const [activity, setActivity] = useState<OverviewActivity | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [period, setPeriod] = useState<Period>(30);

  useEffect(() => {
    let active = true;
    getOverviewActivity(365, 16).then(result => {
      if (active) { setActivity(result); setError(""); }
    }).catch(reason => {
      if (active) setError(reason instanceof Error ? reason.message : "Overview activity could not be loaded.");
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [refreshKey]);

  const daily = activity?.daily ?? [];
  const visibleDays = daily.slice(-period);
  const previousDays = daily.slice(-period * 2, -period);
  const currentTotal = sum(visibleDays.map(item => item.total));
  const previousTotal = sum(previousDays.map(item => item.total));
  const change = previousTotal > 0 ? ((currentTotal - previousTotal) / previousTotal) * 100 : null;
  const sectionTotals = useMemo(() => SECTIONS.map(section => ({
    ...section,
    count: sum(visibleDays.map(day => day.by_section[section.id] ?? 0)),
  })), [visibleDays]);
  const maxSection = Math.max(1, ...sectionTotals.map(item => item.count));
  const monthly = activity?.monthly ?? [];
  const monthlyTotal = sum(monthly.map(item => item.total));
  const monthlyAverage = monthly.length ? monthlyTotal / monthly.length : 0;
  const threatLookups = activity?.section_counts["threat-intel"] ?? 0;
  const unresolvedFindings = findings.filter(item => item.status !== "resolved").length;
  const activeIncidents = incidents.filter(item => ["open", "investigating", "contained"].includes(item.status)).length;
  const eventFeed = activity?.recent ?? [];

  return <section className="overview-bento">
    <header className="ov-heading">
      <div><span className="ov-kicker">OPSAEGIS / SECURITY OPERATIONS</span><h2>Overview</h2><p>Your security posture, activity and response signals in one view.</p></div>
      <div className="ov-live-indicator"><i />{loading ? "SYNCING" : error ? "DATA DELAYED" : "LIVE DATA"}<span>15s refresh</span></div>
    </header>

    {error && <div className="error-banner" role="alert">Live activity feed unavailable: {error}. Existing section records remain visible where loaded.</div>}

    <div className="ov-bento-grid">
      <section className="ov-panel ov-panel-activity">
        <div className="ov-hero-metric">
          <div><span className="ov-label">Recorded security activity</span><strong>{fmt(currentTotal)}</strong><small>Audit events · last {period} days</small></div>
          <div className={"ov-change " + (change !== null && change < 0 ? "down" : "")}>{change === null ? "—" : (change >= 0 ? "↑ " : "↓ ") + Math.abs(change).toFixed(1) + "%"}<small>vs previous period</small></div>
        </div>
        <div className="ov-spark-meta"><span>ACTIVITY TREND</span><span>{visibleDays.length ? dateLabel(visibleDays[0].date) + " — " + dateLabel(visibleDays[visibleDays.length - 1].date) : "No activity data"}</span></div>
        <Sparkline values={visibleDays.map(item => item.total)} />
        <div className="ov-quick-stats">
          <div><span>Assets</span><strong>{fmt(assets.length)}</strong></div>
          <div><span>Open findings</span><strong>{fmt(unresolvedFindings)}</strong></div>
          <div><span>Active incidents</span><strong>{fmt(activeIncidents)}</strong></div>
          <div><span>Threat lookups</span><strong>{fmt(threatLookups)}</strong></div>
        </div>
      </section>

      <section className="ov-panel ov-panel-sessions">
        <PanelHead eyebrow="SOURCE SIGNALS" heading="Activity by section" trailing={<span className="ov-subtle">30 DAYS</span>} />
        <MultiLineChart data={daily} />
        <div className="ov-section-summary">
          {["threat-intel","detections","incidents"].map(id => {
            const section = sectionTotals.find(item => item.id === id)!;
            return <div key={id}><i style={{ background: section.color }}/><span>{section.label}</span><b>{fmt(section.count)}</b></div>;
          })}
        </div>
      </section>

      <section className="ov-panel ov-panel-category">
        <PanelHead eyebrow="WORKSPACE BREAKDOWN" heading="Activity by category" trailing={
          <div className="ov-period-switch" aria-label="Activity period">
            {([7,30,365] as Period[]).map(value => <button key={value} type="button" className={period === value ? "active" : ""} aria-pressed={period === value} onClick={() => setPeriod(value)}>{value === 7 ? "Week" : value === 30 ? "Month" : "Year"}</button>)}
          </div>
        }/>
        <div className="ov-treemap">
          {sectionTotals.filter(item => item.count > 0).sort((a,b) => b.count-a.count).map((item,index) => <div key={item.id} className={"ov-tile ov-tile-" + (index % 5)} style={{ flexGrow: Math.max(1,item.count), "--tile-color": item.color } as React.CSSProperties}>
            <span>{item.label}</span><strong>{fmt(item.count)}</strong><small>{currentTotal ? ((item.count/currentTotal)*100).toFixed(1) : "0.0"}%</small>
          </div>)}
          {!sectionTotals.some(item => item.count > 0) && <div className="ov-no-activity">No audited activity in this period yet.</div>}
        </div>
        <div className="ov-category-table">
          <div><span>Section</span><span>Events</span><span>Share</span></div>
          {sectionTotals.slice().sort((a,b) => b.count-a.count).slice(0,5).map(item => <div key={item.id}><span><i style={{background:item.color}}/>{item.label}</span><b>{fmt(item.count)}</b><small>{currentTotal ? ((item.count/currentTotal)*100).toFixed(1) : "0.0"}%</small></div>)}
        </div>
      </section>

      <section className="ov-panel ov-panel-seasonality">
        <PanelHead eyebrow="LONG-RANGE SIGNALS" heading="Activity rhythm" trailing={<span className="ov-subtle">12 MONTHS</span>} />
        <div className="ov-radar-layout"><RadarChart monthly={monthly}/><div className="ov-radar-stats"><div><small>Monthly average</small><strong>{fmt(Math.round(monthlyAverage))}</strong><span>Audited events / month</span></div><div><small>12-month total</small><strong>{fmt(monthlyTotal)}</strong><span>Recorded activity</span></div></div></div>
        <div className="ov-recent-head"><span>RECENT ACTIVITY</span><span>{eventFeed.length} events</span></div>
        <div className="ov-recent-list">
          {eventFeed.slice(0,4).map(event => <div className="ov-event" key={event.id}><i className={"ov-event-dot " + event.section}/><div><strong>{event.summary}</strong><small>{title(event.section)}{event.record ? " · " + event.record : ""}</small></div><time>{clockLabel(event.occurred_at)}</time></div>)}
          {!eventFeed.length && <p className="ov-no-activity">{loading ? "Loading recent events…" : "No recorded actions in the selected window."}</p>}
        </div>
      </section>
    </div>
    <footer className="ov-footnote">Metrics are calculated from authenticated OpsAegis records and audit events. Read-only page visits are not counted as security activity.{activity?.rows_limited ? " Activity history reached the 10,000-record query limit." : ""}</footer>
  </section>;
}
