import { FormEvent, useEffect, useState } from "react";
import { useLiveRefresh } from "./live-refresh";
import {
  Detection, DetectionNotification, DetectionRule, DetectionScheduler, DetectionStatus,
  ScheduledDetectionRun, evaluateDetections, getDetections, getDetectionRules,
  getDetectionScheduler, getScheduledDetectionRuns, getDetectionNotifications,
  markDetectionNotificationRead, updateDetectionScheduler, updateDetectionStatus,
} from "./api";

function dateLabel(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}
function titleCase(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function DetectionsPanel({ canOperate, isAdmin }: { canOperate: boolean; isAdmin: boolean }) {
  const [items, setItems] = useState<Detection[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [scheduler, setScheduler] = useState<DetectionScheduler | null>(null);
  const [runs, setRuns] = useState<ScheduledDetectionRun[]>([]);
  const [notifications, setNotifications] = useState<DetectionNotification[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function refresh() {
    const [detectionRows, ruleRows, schedule, runRows, notificationRows] = await Promise.all([
      getDetections(), getDetectionRules(), getDetectionScheduler(),
      getScheduledDetectionRuns(), getDetectionNotifications(),
    ]);
    setItems(detectionRows); setRules(ruleRows); setScheduler(schedule);
    setRuns(runRows); setNotifications(notificationRows);
  }
  useLiveRefresh(() => refresh(), { intervalMs: 15000 });
  useEffect(() => {
    void refresh().catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Unable to load detection operations."));
  }, []);

  async function runEvaluation() {
    setBusy(true); setError(""); setMessage("");
    try {
      const result = await evaluateDetections();
      setMessage("Manual evaluation complete · " + result.findings_considered + " findings examined · " +
        result.created + " detections created · " + result.incidents_created + " incidents created.");
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Detection evaluation failed.");
    } finally { setBusy(false); }
  }

  async function saveSchedule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!scheduler) return;
    setBusy(true); setError(""); setMessage("");
    try {
      const saved = await updateDetectionScheduler({
        enabled: scheduler.enabled, interval_seconds: scheduler.interval_seconds,
        window_minutes: scheduler.window_minutes, auth_threshold: scheduler.auth_threshold,
      });
      setScheduler(saved);
      setMessage(saved.enabled ? "Scheduled detection evaluations enabled." : "Scheduled detection evaluations paused.");
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to update the detection schedule.");
    } finally { setBusy(false); }
  }

  async function changeStatus(id: number, status: DetectionStatus) {
    setError(""); setMessage("");
    try {
      await updateDetectionStatus(id, status);
      setMessage("Detection DET-" + id + " moved to " + titleCase(status) + ".");
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to update detection status.");
    }
  }

  async function markRead(id: number) {
    try {
      await markDetectionNotificationRead(id);
      setNotifications(current => current.map(item => item.id === id ? { ...item, read_at: new Date().toISOString() } : item));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to mark notification as read.");
    }
  }

  return <div className="page-content detection-workspace">
    <section className="list-intro"><div><p className="eyebrow">DETERMINISTIC CORRELATION</p><h2>Security detections</h2>
      <p>Scheduled and manual evaluation of persisted Wazuh, CrowdSec, Nuclei and Shannon findings. Evidence remains linked to its source records.</p></div>
      {canOperate && <button className="primary-button compact" onClick={() => void runEvaluation()} disabled={busy}>{busy ? "Working…" : "Run now"}</button>}
    </section>
    {message && <div className="success-banner" role="status">{message}</div>}
    {error && <div className="error-banner" role="alert">{error}</div>}

    <section className="panel">
      <div className="panel-heading"><div><p className="eyebrow">AUTOMATION</p><h3>Detection scheduler</h3></div>
        <span className={"engine-status " + (scheduler?.worker_status === "online" ? "healthy" : "unhealthy")}>{scheduler?.worker_status === "online" ? "Worker online" : "Worker offline"}</span></div>
      {!scheduler ? <p className="integration-note">Loading scheduler configuration…</p> : <>
        <p className="integration-note">Redis: {scheduler.redis_status} · Next run: {dateLabel(scheduler.next_run_at)} · Last enqueued: {dateLabel(scheduler.last_scheduled_at)}</p>
        {scheduler.enabled && scheduler.worker_status !== "online" && <div className="error-banner" role="alert">Scheduling is enabled, but the background worker heartbeat is missing. Jobs will not run until the worker is healthy.</div>}
        <form className="nuclei-target-form" onSubmit={saveSchedule}>
          <label className="inline-check"><input type="checkbox" checked={scheduler.enabled} disabled={!isAdmin} onChange={event => setScheduler({ ...scheduler, enabled: event.target.checked })}/> Enable automatic evaluation</label>
          <label>Evaluation interval
            <select value={scheduler.interval_seconds} disabled={!isAdmin} onChange={event => setScheduler({ ...scheduler, interval_seconds: Number(event.target.value) })}>
              <option value={60}>Every minute</option><option value={300}>Every 5 minutes</option><option value={900}>Every 15 minutes</option><option value={1800}>Every 30 minutes</option><option value={3600}>Every hour</option>
            </select>
          </label>
          <label>Finding window (minutes)<input type="number" min={1} max={1440} value={scheduler.window_minutes} disabled={!isAdmin} onChange={event => setScheduler({ ...scheduler, window_minutes: Number(event.target.value) })}/></label>
          <label>Authentication threshold<input type="number" min={3} max={20} value={scheduler.auth_threshold} disabled={!isAdmin} onChange={event => setScheduler({ ...scheduler, auth_threshold: Number(event.target.value) })}/></label>
          {isAdmin && <button className="primary-button compact" type="submit" disabled={busy}>Save schedule</button>}
        </form>
        {!isAdmin && <p className="integration-note">Only administrators can change the schedule.</p>}
      </>}
    </section>

    <section className="panel">
      <div className="panel-heading"><div><p className="eyebrow">RELIABLE BACKGROUND EXECUTION</p><h3>Scheduled run history</h3></div><span className="tag">{runs.length} recent runs</span></div>
      {runs.length ? <div className="table-wrap"><table><thead><tr><th>Run</th><th>Status</th><th>Attempts</th><th>Window</th><th>Created</th><th>Finished</th></tr></thead><tbody>
        {runs.map(run => <tr key={run.id}><td>RUN-{run.id}</td><td><span className="tag">{titleCase(run.status)}</span>{run.error_code && <small>{run.error_code}</small>}</td><td>{run.attempts}/3</td><td>{run.window_minutes} min · threshold {run.auth_threshold}</td><td>{dateLabel(run.created_at)}</td><td>{dateLabel(run.finished_at)}</td></tr>)}
      </tbody></table></div> : <div className="empty-state"><strong>No scheduled runs yet</strong><p>Enable the schedule as an administrator. Runs are queued by the dedicated Redis-backed worker.</p></div>}
    </section>

    <section className="panel">
      <div className="panel-heading"><div><p className="eyebrow">DETECTION LOGIC</p><h3>Enabled rules</h3></div><span className="tag">Rule-based · explainable</span></div>
      <div className="detection-rule-grid">{rules.map(rule => <article className="engine-card" key={rule.key}>
        <div className="engine-card-top"><span className="engine-indicator healthy"/><span className="engine-status healthy">Enabled</span></div>
        <h4>{rule.name}</h4><p>{rule.description}</p><small>{rule.key} · Sources: {rule.sources.join(", ")} · Window: {rule.default_window_minutes} min · Threshold: {rule.default_threshold}</small>
      </article>)}</div>
    </section>

    <section className="panel">
      <div className="panel-heading"><div><p className="eyebrow">HIGH-PRIORITY ALERTS</p><h3>My notifications</h3></div><span className="tag">{notifications.filter(item => !item.read_at).length} unread</span></div>
      {notifications.length ? <div className="nuclei-target-list">{notifications.map(item => <div className="nuclei-target-row" key={item.id}>
        <div><strong>{item.title}</strong><small>{item.message} · {dateLabel(item.created_at)}</small></div>
        {!item.read_at ? <button className="secondary-button" onClick={() => void markRead(item.id)}>Mark read</button> : <span className="tag">Read</span>}
      </div>)}</div> : <div className="empty-state"><strong>No notifications</strong><p>New high and critical detections will appear here for active analysts and administrators.</p></div>}
    </section>

    <section className="panel data-panel">
      <div className="panel-heading"><div><p className="eyebrow">CORRELATED EVIDENCE</p><h3>Detection history</h3></div><span className="tag">{items.length} records · max 100</span></div>
      {items.length ? <div className="table-wrap"><table><thead><tr><th>Detection</th><th>Rule</th><th>Severity</th><th>Evidence</th><th>Incident</th><th>Lifecycle</th><th>Last seen</th></tr></thead><tbody>
        {items.map(item => <tr key={item.id}><td><strong>{item.title}</strong><small>DET-{item.id} · {item.fingerprint.slice(0, 12)}</small></td>
          <td>{item.rule_key}</td><td><span className={"severity severity-" + item.severity}>{item.severity}</span></td>
          <td>{item.finding_ids.map(id => "F-" + id).join(", ")}</td><td>{item.incident_id ? "INC-" + item.incident_id : "—"}</td>
          <td>{canOperate ? <select aria-label={"Update detection " + item.id + " lifecycle"} value={item.status} onChange={event => void changeStatus(item.id, event.target.value as DetectionStatus)}>
            {(["new", "acknowledged", "investigating", "resolved"] as DetectionStatus[]).filter(status => status === item.status || (item.status === "new" && status === "acknowledged") || (item.status === "acknowledged" && status === "investigating") || (item.status === "investigating" && ["acknowledged", "resolved"].includes(status))).map(status => <option key={status} value={status}>{titleCase(status)}</option>)}
          </select> : <span className="tag">{titleCase(item.status)}</span>}</td>
          <td>{dateLabel(item.last_seen_at)}</td></tr>)}
      </tbody></table></div> : <div className="empty-state"><span className="empty-mark">—</span><strong>No correlated detections</strong><p>Run correlation after real engine findings have been collected. No synthetic telemetry is generated.</p></div>}
    </section>
  </div>;
}
