import { FormEvent, useEffect, useState } from "react";
import {
  getOperationsTrends, getOperationalThresholds, updateOperationalThresholds,
  OperationalThresholds, OperationsTrends,
} from "./api";

function dateInput(value: Date): string {
  return value.toISOString();
}
function labelDate(value: string, bucket: "day" | "week"): string {
  const date = new Date(value);
  return bucket === "week"
    ? date.toLocaleDateString(undefined, { month: "short", day: "numeric" })
    : date.toLocaleDateString(undefined, { month: "numeric", day: "numeric" });
}

export function OperationsPanel({ isAdmin, refreshKey }: { isAdmin: boolean; refreshKey: number }) {
  const [trends, setTrends] = useState<OperationsTrends | null>(null);
  const [thresholds, setThresholds] = useState<OperationalThresholds | null>(null);
  const [draft, setDraft] = useState<OperationalThresholds | null>(null);
  const [bucket, setBucket] = useState<"day" | "week">("day");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    let active = true;
    setLoading(true);
    const until = new Date();
    const since = new Date(until.getTime() - 30 * 86400000);
    Promise.all([getOperationsTrends(dateInput(since), dateInput(until), bucket), getOperationalThresholds()])
      .then(([trendData, thresholdData]) => {
        if (!active) return;
        setTrends(trendData);
        setThresholds(thresholdData);
        setDraft(thresholdData);
        setError("");
      })
      .catch((reason: unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : "Operational metrics could not be loaded.");
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [bucket, refreshKey]);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!draft) return;
    setSaving(true); setError(""); setMessage("");
    try {
      const updated = await updateOperationalThresholds({
        collection_failure_rate_percent: draft.collection_failure_rate_percent,
        source_stale_after_minutes: draft.source_stale_after_minutes,
        detection_to_incident_minutes: draft.detection_to_incident_minutes,
        incident_resolution_minutes: draft.incident_resolution_minutes,
      });
      setThresholds(updated); setDraft(updated); setMessage("Operational thresholds saved.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Thresholds could not be saved.");
    } finally { setSaving(false); }
  }

  const points = trends?.points ?? [];
  const maxRuns = Math.max(1, ...points.map((point) => point.collection_runs));
  const maxEvents = Math.max(1, ...points.map((point) => point.detections + point.incidents));
  return <section className="panel operations-panel">
    <div className="panel-heading">
      <div><p className="eyebrow">PHASE 6.4 · OPERATIONAL REPORTING</p><h3>Operational trends</h3></div>
      <label className="trend-bucket">BUCKET
        <select value={bucket} onChange={(event) => setBucket(event.target.value as "day" | "week")}>
          <option value="day">Daily</option><option value="week">Weekly</option>
        </select>
      </label>
    </div>
    {loading && <p className="trend-note">Loading persisted operational metrics…</p>}
    {error && <p className="trend-error" role="alert">{error}</p>}
    {!loading && !error && trends && <>
      <p className="trend-note">UTC · {new Date(trends.window.since).toLocaleDateString()} – {new Date(trends.window.until).toLocaleDateString()} · persisted records only</p>
      <div className="trend-grid">
        <article className="trend-chart">
          <div className="trend-chart-heading"><strong>Collection runs</strong><span>Successful / failed</span></div>
          <div className="trend-bars" role="img" aria-label="Daily collection runs, successful and failed">
            {points.map((point) => <div className="trend-column" key={point.start} title={labelDate(point.start,bucket)+": "+point.collection_succeeded+" succeeded, "+point.collection_failed+" failed"}>
              <div className="trend-stack" style={{height:Math.max(3,point.collection_runs/maxRuns*100)+"%"}}>
                <i className="trend-success" style={{height:(point.collection_succeeded/Math.max(1,point.collection_runs)*100)+"%"}} />
                <i className="trend-failed" style={{height:(point.collection_failed/Math.max(1,point.collection_runs)*100)+"%"}} />
              </div><small>{labelDate(point.start,bucket)}</small>
            </div>)}
          </div>
          {!points.some((point)=>point.collection_runs>0) && <p className="trend-empty">No collection runs recorded in this window.</p>}
        </article>
        <article className="trend-chart">
          <div className="trend-chart-heading"><strong>Detection & incident volume</strong><span>Created per bucket</span></div>
          <div className="trend-bars" role="img" aria-label="Detection and incident counts by time bucket">
            {points.map((point) => <div className="trend-column" key={point.start} title={labelDate(point.start,bucket)+": "+point.detections+" detections, "+point.incidents+" incidents"}>
              <div className="trend-stack" style={{height:Math.max(3,(point.detections+point.incidents)/maxEvents*100)+"%"}}>
                <i className="trend-detections" style={{height:(point.detections/Math.max(1,point.detections+point.incidents)*100)+"%"}} />
                <i className="trend-incidents" style={{height:(point.incidents/Math.max(1,point.detections+point.incidents)*100)+"%"}} />
              </div><small>{labelDate(point.start,bucket)}</small>
            </div>)}
          </div>
          {!points.some((point)=>point.detections+point.incidents>0) && <p className="trend-empty">No detections or incidents recorded in this window.</p>}
        </article>
      </div>
      {trends.rows_limited && <p className="trend-warning">A query reached the 10,000-row safety cap; these trends may be incomplete.</p>}
      <p className="trend-note">{trends.limitations.join(" ")}</p>
    </>}
    {thresholds?.active_alerts && <div className="threshold-alerts" aria-live="polite"><strong>{thresholds.active_alerts.length ? `${thresholds.active_alerts.length} threshold alert(s)` : "No threshold breaches in the last 7 days"}</strong>{thresholds.active_alerts.map((alert,index)=><p key={alert.code+String(alert.source)+index}>{alert.message}</p>)}</div>}
    {isAdmin && draft && <form className="threshold-form" onSubmit={save}>
      <div className="threshold-heading"><div><p className="eyebrow">ADMINISTRATION</p><h4>Alert thresholds</h4></div><span>Threshold configuration only · no automated response</span></div>
      <div className="threshold-fields">
        <label>Collection failure rate (%)<input type="number" min="1" max="100" value={draft.collection_failure_rate_percent} onChange={(e)=>setDraft({...draft,collection_failure_rate_percent:Number(e.target.value)})} required /></label>
        <label>Source stale after (minutes)<input type="number" min="5" max="10080" value={draft.source_stale_after_minutes} onChange={(e)=>setDraft({...draft,source_stale_after_minutes:Number(e.target.value)})} required /></label>
        <label>Detection → incident (minutes)<input type="number" min="1" max="1440" value={draft.detection_to_incident_minutes} onChange={(e)=>setDraft({...draft,detection_to_incident_minutes:Number(e.target.value)})} required /></label>
        <label>Incident resolution (minutes)<input type="number" min="1" max="10080" value={draft.incident_resolution_minutes} onChange={(e)=>setDraft({...draft,incident_resolution_minutes:Number(e.target.value)})} required /></label>
      </div>
      <div className="threshold-actions"><button className="primary-button compact" type="submit" disabled={saving}>{saving ? "Saving…" : "Save thresholds"}</button>{message && <span className="threshold-success" role="status">{message}</span>}</div>
    </form>}
  </section>;
}
