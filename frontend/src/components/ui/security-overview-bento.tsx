import { useEffect, useMemo, useState } from "react";
import type { Asset, Finding, Incident, OverviewActivity } from "../../api";
import { getOverviewActivity } from "../../api";
import { AnalyticsBento, type AnalyticsBentoProps } from "./analytics-bento";

type Props = { assets: Asset[]; findings: Finding[]; incidents: Incident[]; refreshKey: number };
type PeriodDays = 7 | 30 | 365;

const SECTIONS = [
  { id: "assets", label: "Assets", group: "inventory" },
  { id: "findings", label: "Findings", group: "risk" },
  { id: "vulnerabilities", label: "Vulnerabilities", group: "risk" },
  { id: "detections", label: "Detections", group: "response" },
  { id: "incidents", label: "Incidents", group: "response" },
  { id: "integrations", label: "Integrations", group: "inventory" },
  { id: "threat-intel", label: "Threat Intel", group: "intel" },
  { id: "playbooks", label: "Playbooks", group: "response" },
  { id: "users", label: "Users & Roles", group: "governance" },
  { id: "reports", label: "Reports", group: "governance" },
  { id: "settings", label: "Settings", group: "governance" },
] as const;

const GROUPS = [
  { id: "inventory", name: "Attack surface", color: "var(--oa-blue)", ink: "light" as const },
  { id: "risk", name: "Risk & exposure", color: "var(--oa-cyan)", ink: "light" as const },
  { id: "response", name: "Detection & response", color: "var(--oa-teal)", ink: "light" as const },
  { id: "intel", name: "Threat intelligence", color: "var(--oa-amber)", ink: "light" as const },
  { id: "governance", name: "Governance", color: "var(--oa-steel)", ink: "light" as const },
];

const fmt = (value: number) => Math.round(value).toLocaleString();
const sum = (values: number[]) => values.reduce((total, value) => total + value, 0);
const dateLabel = (value: string) => new Date(value + "T00:00:00Z").toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
const monthLabel = (value: string) => new Date(value + "-01T00:00:00Z").toLocaleDateString(undefined, { month: "short", timeZone: "UTC" });
const timeLabel = (value: string) => new Date(value).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });

function deltaLabel(current: number, previous: number) {
  if (previous <= 0) return current > 0 ? "↑ New activity" : "—";
  const change = ((current - previous) / previous) * 100;
  return (change >= 0 ? "↑ " : "↓ ") + Math.abs(change).toFixed(1) + "%";
}

function countSection(days: OverviewActivity["daily"], section: string) {
  return sum(days.map(day => day.by_section[section] ?? 0));
}

function makeZeroDays(count: number) {
  return Array.from({ length: count }, (_, index) => ({
    date: new Date(Date.now() - (count - index - 1) * 86400000).toISOString().slice(0, 10),
    total: 0,
    by_section: {} as Record<string, number>,
  }));
}

function buildSeasonality(activity: OverviewActivity | null, incidents: Incident[], findings: Finding[]) {
  const monthly = activity?.monthly ?? [];
  const years = [...new Set(monthly.map(item => Number(item.month.slice(0, 4))))].sort((a, b) => b - a);
  const yearList = years.length ? years : [new Date().getUTCFullYear()];
  const activeIncidents = incidents.filter(item => ["open", "investigating", "contained"].includes(item.status)).length;
  const openFindings = findings.filter(item => item.status !== "resolved").length;
  return {
    title: "Security activity rhythm",
    axis: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
    years: yearList.map(year => {
      const values = Array.from({ length: 12 }, (_, index) => {
        const key = year + "-" + String(index + 1).padStart(2, "0");
        return monthly.find(item => item.month === key)?.total ?? 0;
      });
      const total = sum(values);
      const peak = Math.max(0, ...values);
      const peakIndex = values.indexOf(peak);
      const rows = (activity?.recent ?? []).slice(0, 3).map(event => ({
        label: event.summary,
        value: timeLabel(event.occurred_at),
      }));
      if (!rows.length) rows.push({ label: "No recent recorded activity", value: "—" });
      return {
        label: String(year),
        values,
        stats: [
          { label: "Active incidents", value: activeIncidents, delta: "—", note: "current open cases" },
          { label: "Open findings", value: openFindings, delta: "—", note: "not yet resolved" },
        ],
        rows: [
          { label: "Assets monitored", value: fmt(0) },
          { label: "Peak activity month", value: peak ? monthLabel(year + "-" + String(peakIndex + 1).padStart(2, "0")) + " · " + fmt(peak) : "No events" },
          ...rows,
        ],
      };
    }),
  };
}

export function SecurityOverviewBento({ assets, findings, incidents, refreshKey }: Props) {
  const [activity, setActivity] = useState<OverviewActivity | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    getOverviewActivity(730, 16).then(result => {
      if (!active) return;
      setActivity(result);
      setError("");
      setUpdatedAt(new Date().toISOString());
    }).catch(reason => {
      if (active) setError(reason instanceof Error ? reason.message : "Overview activity could not be loaded.");
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [refreshKey]);

  const daily = activity?.daily?.length ? activity.daily : makeZeroDays(730);
  const last30 = daily.slice(-30);
  const previous30 = daily.slice(-60, -30);
  const total30 = sum(last30.map(day => day.total));
  const previousTotal30 = sum(previous30.map(day => day.total));
  const signalNow = countSection(last30, "detections") + countSection(last30, "incidents");
  const signalPrevious = countSection(previous30, "detections") + countSection(previous30, "incidents");
  const sectionTotals = useMemo(() => SECTIONS.map(section => ({
    ...section,
    values: ([7, 30, 365] as PeriodDays[]).map(days => countSection(daily.slice(-days), section.id)),
  })), [daily]);
  const periodTotals = ([7, 30, 365] as PeriodDays[]).map((days, index) => {
    const current = daily.slice(-days);
    const previous = daily.slice(-days * 2, -days);
    const currentTotal = sum(current.map(day => day.total));
    const previousTotal = sum(previous.map(day => day.total));
    return {
      label: index === 0 ? "7 days" : index === 1 ? "30 days" : "365 days",
      total: currentTotal,
      delta: deltaLabel(currentTotal, previousTotal),
      compare: "vs previous " + days + " days",
    };
  });

  const topSections = [...sectionTotals].sort((a, b) => b.values[1] - a.values[1]).slice(0, 5);
  const recent = activity?.recent ?? [];
  const seasonality = buildSeasonality(activity, incidents, findings);
  seasonality.years = seasonality.years.map(year => ({
    ...year,
    rows: [
      { label: "Assets monitored", value: fmt(assets.length) },
      ...year.rows.slice(1),
    ],
  }));

  const categories: AnalyticsBentoProps["categories"] = {
    title: "Workspace activity breakdown",
    groups: GROUPS,
    periods: periodTotals,
    items: sectionTotals.map(section => ({
      name: section.label,
      group: section.group,
      values: section.values,
    })),
    table: {
      columns: ["Workspace", "7D", "30D", "365D"],
      rows: topSections.map(section => ({
        label: section.label,
        values: section.values.map(fmt),
      })),
    },
  };

  const currentYear = new Date().getUTCFullYear();
  const activitySeries = last30.map(day => ({ label: dateLabel(day.date), value: day.total }));
  const sessions: AnalyticsBentoProps["sessions"] = {
    label: "Detection & incident signals",
    value: signalNow,
    delta: deltaLabel(signalNow, signalPrevious),
    note: "Recorded detection and incident actions · last 30 days",
    desktop: [
      last30.map(day => day.by_section.detections ?? 0),
      previous30.map(day => day.by_section.detections ?? 0),
    ],
    mobile: [
      last30.map(day => day.by_section.incidents ?? 0),
      previous30.map(day => day.by_section.incidents ?? 0),
    ],
    labels: {
      desktop: "Detections",
      mobile: "Incidents",
      prior: "Previous 30 days",
      current: "Daily activity",
      points: last30.map(day => dateLabel(day.date)),
    },
  };

  const revenue: AnalyticsBentoProps["revenue"] = {
    label: "Recorded security activity",
    value: total30,
    delta: deltaLabel(total30, previousTotal30),
    note: "Authenticated audit events across all workspaces",
    caption: "DAILY EVENTS · LAST 30 DAYS",
    series: activitySeries.length ? activitySeries : [{ label: "No data", value: 0 }],
  };

  const liveColors: NonNullable<AnalyticsBentoProps["colors"]> = {
    revenue: ["var(--oa-cyan)", "var(--oa-blue)"],
    desktop: ["var(--oa-blue)", "var(--oa-cyan)"],
    mobile: ["var(--oa-teal)", "var(--oa-amber)"],
    radar: "var(--oa-teal)",
  };

  return (
    <section className="ops-analytics-overview">
      <header className="ops-analytics-heading">
        <div className="ops-analytics-title">
          <span className="ops-analytics-kicker">OPSAEGIS / SECURITY OPERATIONS</span>
          <h2>Security command center</h2>
          <p>Live operational signals, exposure and response activity across every workspace.</p>
        </div>
        <div className="ops-analytics-status" role="status">
          <span className={"ops-analytics-status-dot" + (error ? " is-error" : "")} />
          <span>{loading ? "SYNCING" : error ? "DATA DELAYED" : "LIVE DATA"}</span>
          <i />
          <small>{updatedAt ? "Updated " + timeLabel(updatedAt) : "15s refresh"}</small>
        </div>
      </header>

      {error && <div className="error-banner" role="alert">Live activity feed unavailable: {error}. Previously loaded workspace records are retained.</div>}

      <div className="ops-analytics-bento">
        <AnalyticsBento
          currency=""
          revenue={revenue}
          sessions={sessions}
          categories={categories}
          seasonality={seasonality}
          colors={liveColors}
          credit={false}
          className="ops-analytics-component"
        />
      </div>

      <footer className="ops-analytics-footnote">
        <span>LIVE DATA SOURCE</span>
        Authenticated OpsAegis records and persisted audit events · automatic refresh every 15 seconds and after successful actions.
        {activity?.rows_limited ? " Activity history reached the backend query limit." : ""}
        {recent.length ? " Latest event: " + recent[0].summary + "." : " No recent activity has been recorded."}
      </footer>
    </section>
  );
}
