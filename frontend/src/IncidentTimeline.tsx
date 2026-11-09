import { FormEvent, useCallback, useEffect, useState } from "react";
import { addIncidentNote, downloadIncidentEvidence, getIncidentTimeline, IncidentTimelineEvent } from "./api";

function dateLabel(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

export function IncidentTimeline({ incidentId, canOperate }: { incidentId: number; canOperate: boolean }) {
  const [events, setEvents] = useState<IncidentTimelineEvent[]>([]);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    const result = await getIncidentTimeline(incidentId);
    setEvents(result.events);
  }, [incidentId]);

  useEffect(() => {
    let active = true;
    getIncidentTimeline(incidentId).then((result) => { if (active) setEvents(result.events); })
      .catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : "Timeline could not be loaded."); });
    return () => { active = false; };
  }, [incidentId]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!note.trim()) return;
    setBusy(true); setError("");
    try {
      await addIncidentNote(incidentId, note.trim());
      setNote("");
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Note could not be saved.");
    } finally { setBusy(false); }
  }

  async function exportEvidence() {
    setBusy(true); setError("");
    try { await downloadIncidentEvidence(incidentId); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Evidence export failed."); }
    finally { setBusy(false); }
  }

  return <section className="incident-timeline">
    <div className="panel-heading"><div><p className="eyebrow">PROVENANCE-AWARE RECORD</p><h4>Investigation timeline</h4></div>
      <button className="secondary-button compact" disabled={busy} onClick={() => void exportEvidence()}>Export redacted evidence</button>
    </div>
    {error && <div className="inline-error" role="alert">{error}</div>}
    {canOperate && <form className="timeline-note-form" onSubmit={submit}>
      <label htmlFor={"incident-note-" + incidentId}>Add analyst note</label>
      <textarea id={"incident-note-" + incidentId} value={note} onChange={(event) => setNote(event.target.value)} maxLength={5000} rows={3} placeholder="Record an observation, decision or next step…" />
      <button className="primary-button compact" type="submit" disabled={busy || !note.trim()}>{busy ? "Saving…" : "Add note"}</button>
    </form>}
    {events.length ? <ol className="timeline-list">{events.map((item) => <li key={item.id}>
      <span className="timeline-marker" />
      <div className="timeline-event"><div className="timeline-event-head"><strong>{item.type.replaceAll(".", " · ")}</strong><time>{dateLabel(item.occurred_at)}</time></div>
        <p>{item.summary}</p><small>Provenance: {item.provenance}{item.actor_user_id ? " · User " + item.actor_user_id : ""}</small>
        {Object.keys(item.details).length > 0 && <pre>{JSON.stringify(item.details, null, 2)}</pre>}
      </div>
    </li>)}</ol> : <div className="empty-state"><strong>No timeline events available</strong><p>Incident changes, correlated detections, linked findings and analyst notes will appear here.</p></div>}
    <p className="integration-note">Timeline entries distinguish OpsAegis audit records, source findings, correlation-engine detections and analyst-authored notes. Lists are bounded and may not represent unlimited history.</p>
  </section>;
}
