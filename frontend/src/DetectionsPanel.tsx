import { useEffect, useState } from "react";
import { Detection, DetectionRule, evaluateDetections, getDetections, getDetectionRules } from "./api";

function dateLabel(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

export function DetectionsPanel({ canOperate }: { canOperate: boolean }) {
  const [items, setItems] = useState<Detection[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function refresh() {
    const [detectionRows, ruleRows] = await Promise.all([getDetections(), getDetectionRules()]);
    setItems(detectionRows);
    setRules(ruleRows);
  }
  useEffect(() => { void refresh().catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Unable to load detections.")); }, []);

  async function runEvaluation() {
    setBusy(true); setError(""); setMessage("");
    try {
      const result = await evaluateDetections();
      setMessage("Evaluation complete · " + result.findings_considered + " findings examined · " +
        result.created + " detections created · " + result.incidents_created + " incidents created.");
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Detection evaluation failed.");
    } finally { setBusy(false); }
  }

  return <div className="page-content detection-workspace">
    <section className="list-intro"><div><p className="eyebrow">DETERMINISTIC CORRELATION</p><h2>Security detections</h2>
      <p>Correlates persisted Wazuh and CrowdSec findings. Each detection retains source finding IDs and links to its generated incident.</p></div>
      {canOperate && <button className="primary-button compact" onClick={() => void runEvaluation()} disabled={busy}>{busy ? "Evaluating…" : "Run correlation"}</button>}
    </section>
    {message && <div className="success-banner" role="status">{message}</div>}
    {error && <div className="error-banner" role="alert">{error}</div>}
    <section className="panel">
      <div className="panel-heading"><div><p className="eyebrow">DETECTION LOGIC</p><h3>Enabled rules</h3></div><span className="tag">Rule-based · explainable</span></div>
      <div className="detection-rule-grid">{rules.map(rule => <article className="engine-card" key={rule.key}>
        <div className="engine-card-top"><span className="engine-indicator healthy"/><span className="engine-status healthy">Enabled</span></div>
        <h4>{rule.name}</h4><p>{rule.description}</p><small>{rule.key} · Sources: {rule.sources.join(", ")} · Window: {rule.default_window_minutes} min · Threshold: {rule.default_threshold}</small>
      </article>)}</div>
    </section>
    <section className="panel data-panel">
      <div className="panel-heading"><div><p className="eyebrow">CORRELATED EVIDENCE</p><h3>Detection history</h3></div><span className="tag">{items.length} records · max 100</span></div>
      {items.length ? <div className="table-wrap"><table><thead><tr><th>Detection</th><th>Rule</th><th>Severity</th><th>Evidence</th><th>Incident</th><th>Last seen</th></tr></thead><tbody>
        {items.map(item => <tr key={item.id}><td><strong>{item.title}</strong><small>DET-{item.id} · {item.fingerprint.slice(0, 12)}</small></td>
          <td>{item.rule_key}</td><td><span className={"severity severity-" + item.severity}>{item.severity}</span></td>
          <td>{item.finding_ids.map(id => "F-" + id).join(", ")}</td><td>{item.incident_id ? "INC-" + item.incident_id : "—"}</td><td>{dateLabel(item.last_seen_at)}</td></tr>)}
      </tbody></table></div> : <div className="empty-state"><span className="empty-mark">—</span><strong>No correlated detections</strong><p>Run correlation after real Wazuh or CrowdSec findings have been collected. No synthetic telemetry is generated.</p></div>}
    </section>
  </div>;
}
