import { useCallback, useEffect, useState } from "react";
import { useLiveRefresh } from "./live-refresh";
import {
  CollectionRun, CollectionSchedule, getCollectionRuns, getCollectionSchedules,
  requestCollectionRun, updateCollectionSchedule,
} from "./api";

function dateLabel(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

export function CollectionPanel({ canOperate, isAdmin }: { canOperate: boolean; isAdmin: boolean }) {
  const [schedules, setSchedules] = useState<CollectionSchedule[]>([]);
  const [runs, setRuns] = useState<CollectionRun[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const refresh = useCallback(async () => {
    const [nextSchedules, nextRuns] = await Promise.all([getCollectionSchedules(), getCollectionRuns()]);
    setSchedules(nextSchedules);
    setRuns(nextRuns);
  }, []);

  useLiveRefresh(() => refresh(), { intervalMs: 15000 });

  useEffect(() => {
    let active = true;
    Promise.all([getCollectionSchedules(), getCollectionRuns()]).then(([nextSchedules, nextRuns]) => {
      if (active) { setSchedules(nextSchedules); setRuns(nextRuns); }
    }).catch((reason: unknown) => {
      if (active) setError(reason instanceof Error ? reason.message : "Collection status could not be loaded.");
    });
    return () => { active = false; };
  }, []);

  async function save(item: CollectionSchedule) {
    setBusy(item.source); setError(""); setMessage("");
    try {
      await updateCollectionSchedule(item.source, {
        enabled: item.enabled, interval_seconds: item.interval_seconds,
        lookback_minutes: item.lookback_minutes,
      });
      await refresh();
      setMessage("Schedule saved. The first run is queued after the configured interval.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Schedule could not be saved.");
    } finally { setBusy(null); }
  }

  async function runNow(source: string) {
    setBusy(source); setError(""); setMessage("");
    try {
      await requestCollectionRun(source);
      await refresh();
      setMessage("Collection run queued. Refresh the run history to follow its status.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Collection run could not be queued.");
    } finally { setBusy(null); }
  }

  return <section className="panel collection-panel">
    <div className="panel-heading"><div><p className="eyebrow">PHASE 6 · READ-ONLY AUTOMATION</p><h3>Collection orchestration</h3></div>
      <button className="secondary-button compact" onClick={() => void refresh().catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Refresh failed."))}>Refresh runs ↻</button>
    </div>
    <p className="integration-note">Only the Wazuh Manager inventory and Wazuh Indexer alert readers are allowlisted. Schedules are disabled until an administrator enables them. No scanner or response action is invoked.</p>
    {error && <div className="inline-error" role="alert">{error}</div>}
    {message && <div className="success-banner" role="status">{message}</div>}
    <div className="collection-schedules">
      {schedules.map((item) => <article className="collection-schedule" key={item.source}>
        <div className="collection-schedule-title"><div><strong>{item.source === "wazuh-manager-agents" ? "Wazuh Manager · Agent inventory" : "Wazuh Indexer · Alert window"}</strong><small>{item.description}</small></div><span className={"tag " + (item.enabled ? "status-enabled" : "")}>{item.enabled ? "Enabled" : "Paused"}</span></div>
        <div className="collection-fields">
          <label className="collection-toggle"><input type="checkbox" checked={item.enabled} disabled={!isAdmin || busy === item.source} onChange={(event) => setSchedules((current) => current.map((row) => row.source === item.source ? {...row, enabled:event.target.checked} : row))}/> Schedule enabled</label>
          <label>Interval (seconds)<input type="number" min={60} max={86400} step={60} value={item.interval_seconds} disabled={!isAdmin} onChange={(event) => setSchedules((current) => current.map((row) => row.source === item.source ? {...row, interval_seconds:Number(event.target.value)} : row))}/></label>
          <label>Lookback (minutes)<input type="number" min={1} max={43199} value={item.lookback_minutes} disabled={!isAdmin} onChange={(event) => setSchedules((current) => current.map((row) => row.source === item.source ? {...row, lookback_minutes:Number(event.target.value)} : row))}/></label>
        </div>
        <div className="collection-schedule-foot"><small>Next run: {dateLabel(item.next_run_at)} · Last scheduled: {dateLabel(item.last_run_at)}</small><div>
          {isAdmin && <button className="primary-button compact" disabled={busy === item.source} onClick={() => void save(item)}>{busy === item.source ? "Saving…" : "Save schedule"}</button>}
          {canOperate && <button className="secondary-button compact" disabled={busy === item.source} onClick={() => void runNow(item.source)}>Run now</button>}
        </div></div>
      </article>)}
    </div>
    <div className="panel-heading collection-history-heading"><div><p className="eyebrow">DURABLE EXECUTION RECORDS</p><h4>Recent collection runs</h4></div><span className="tag">{runs.length} records</span></div>
    {runs.length ? <div className="table-wrap"><table><thead><tr><th>Source</th><th>Status</th><th>Attempts</th><th>Received</th><th>Created / updated</th><th>Truncated?</th><th>Started</th><th>Duration</th><th>Window</th><th>Error code</th></tr></thead><tbody>{runs.map((run) => <tr key={run.id}><td><strong>{run.source}</strong><small>RUN-{run.id}</small></td><td><span className="tag">{run.status}</span></td><td>{run.attempts}</td><td>{run.received}</td><td>{run.created} / {run.updated}</td><td>{run.truncated_possible ? "Possible" : "No"}</td><td>{dateLabel(run.started_at)}</td><td>{run.duration_ms === null ? "—" : (run.duration_ms / 1000).toFixed(2) + "s"}</td><td>{run.window_start_at ? dateLabel(run.window_start_at) + " → " + dateLabel(run.window_end_at) : "Snapshot"}</td><td>{run.error_code || "—"}</td></tr>)}</tbody></table></div> : <div className="empty-state"><strong>No collection runs yet</strong><p>Enable a schedule or queue a manual read-only run.</p></div>}
    {!isAdmin && <p className="integration-note">Only administrators can change schedule settings. Analysts can request an immediate run.</p>}
  </section>;
}
