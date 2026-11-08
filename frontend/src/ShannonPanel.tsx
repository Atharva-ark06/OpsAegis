import { FormEvent, useEffect, useState } from "react";
import {
  ShannonHealth, ShannonTarget, ShannonScan, getShannonHealth, getShannonTargets,
  getShannonScans, registerShannonTarget, startShannonScan, syncShannonScan,
} from "./api";

function formatWhen(value: string | null): string {
  if (!value) return "Not started";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

export function ShannonPanel({ canOperate, isAdmin }: { canOperate: boolean; isAdmin: boolean }) {
  const [health, setHealth] = useState<ShannonHealth | null>(null);
  const [targets, setTargets] = useState<ShannonTarget[]>([]);
  const [scans, setScans] = useState<ShannonScan[]>([]);
  const [name, setName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [repository, setRepository] = useState("");
  const [authorization, setAuthorization] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function refresh() {
    const results = await Promise.allSettled([getShannonHealth(), getShannonTargets(), getShannonScans()]);
    if (results[0].status === "fulfilled") setHealth(results[0].value);
    if (results[1].status === "fulfilled") setTargets(results[1].value);
    if (results[2].status === "fulfilled") setScans(results[2].value);
    const failed = results.find((result) => result.status === "rejected");
    if (failed?.status === "rejected") setError(failed.reason instanceof Error ? failed.reason.message : "Unable to load Shannon data.");
  }

  useEffect(() => { if (canOperate) void refresh(); }, [canOperate]);

  async function addTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError(""); setMessage("");
    try {
      await registerShannonTarget({
        name: name.trim(), target_url: targetUrl.trim(),
        source_repository: repository.trim(), authorization_reference: authorization.trim(),
      });
      setName(""); setTargetUrl(""); setRepository(""); setAuthorization("");
      setMessage("Authorized staging target registered.");
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Target registration failed.");
    } finally { setBusy(false); }
  }

  async function runScan(id: number) {
    setBusy(true); setError(""); setMessage("");
    try {
      const result = await startShannonScan(id);
      setMessage("Shannon job " + result.scan.status + ". Sync scan history to retrieve its final report.");
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Shannon dispatch failed.");
    } finally { setBusy(false); }
  }

  async function syncScan(id: number) {
    setBusy(true); setError(""); setMessage("");
    try {
      const result = await syncShannonScan(id);
      setMessage("Scan " + result.scan.status + ": " + result.received + " validated findings received, " +
        result.inserted + " new and " + result.updated + " updated.");
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to sync Shannon scan.");
    } finally { setBusy(false); }
  }

  if (!canOperate) return null;
  return <section className="shannon-workspace">
    <div className="panel-heading">
      <div><p className="eyebrow">AUTHORIZED AI APPLICATION PENTESTING</p><h3>Shannon assessment workspace</h3></div>
      <span className={"engine-status " + (health?.status || "unknown")}>{health?.execution_enabled ? "Isolated runner online" : "Runner unavailable"}</span>
    </div>
    <p className="integration-note">
      Shannon performs real exploitation. Register only owned staging/lab systems with written approval.
      Dispatch is administrator-only and requires a separately deployed isolated runner.
    </p>
    {error && <div className="inline-error" role="alert">{error}</div>}
    {message && <div className="success-banner" role="status">{message}</div>}
    {isAdmin && <form className="shannon-target-form" onSubmit={addTarget}>
      <label>Target name<input value={name} onChange={(event) => setName(event.target.value)} minLength={2} maxLength={120} required placeholder="Authorized staging application" /></label>
      <label>HTTPS staging URL<input type="url" value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} required placeholder="https://staging.example.com" /></label>
      <label>GitHub source repository<input type="url" value={repository} onChange={(event) => setRepository(event.target.value)} required placeholder="https://github.com/org/application" /></label>
      <label>Written authorization reference<input value={authorization} onChange={(event) => setAuthorization(event.target.value)} minLength={12} maxLength={500} required placeholder="Approval / change ticket ID" /></label>
      <button className="primary-button compact" disabled={busy}>Register authorized target</button>
    </form>}
    <div className="nuclei-target-list">
      <h4>Authorized targets</h4>
      {targets.length ? targets.map((target) => <div className="nuclei-target-row" key={target.id}>
        <div><strong>{target.name}</strong><small>{target.target_url} · {target.source_repository}</small></div>
        <button className="primary-button compact" disabled={busy || !health?.execution_enabled || !target.enabled || !isAdmin}
          onClick={() => void runScan(target.id)}>Dispatch assessment</button>
      </div>) : <div className="empty-state"><strong>No authorized targets</strong><p>An administrator must register a staging target and source repository.</p></div>}
    </div>
    <div className="nuclei-target-list">
      <h4>Assessment history</h4>
      {scans.length ? scans.slice(0, 12).map((scan) => <div className="nuclei-target-row" key={scan.id}>
        <div><strong>Assessment #{scan.id} · Target #{scan.target_id}</strong>
          <small>{scan.status} · {scan.findings_count} findings · Requested {formatWhen(scan.created_at)}</small></div>
        <button className="secondary-button compact" disabled={busy || ["completed", "failed", "cancelled"].includes(scan.status) || !scan.runner_job_id}
          onClick={() => void syncScan(scan.id)}>Sync result</button>
      </div>) : <div className="empty-state"><strong>No assessments yet</strong><p>Runner execution history will appear here after a dispatch.</p></div>}
    </div>
    {!health?.execution_enabled && <p className="integration-note">
      Execution remains disabled until SHANNON_ENABLED=true and the external bridge passes its HTTPS health check.
      No Shannon engine or provider key is bundled with OpsAegis.
    </p>}
  </section>;
}
