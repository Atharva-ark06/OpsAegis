import { useEffect, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";
import {
  addIncidentNote, downloadIncidentAttachment, downloadIncidentEvidence,
  getIncidentAttachments, getIncidentTimeline, uploadIncidentAttachment,
} from "./api";
import type { IncidentEvidenceAttachment, IncidentTimelineEvent } from "./api";


function dateLabel(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

function sizeLabel(value: number): string {
  if (value < 1024) return value + " B";
  if (value < 1024 * 1024) return (value / 1024).toFixed(1) + " KB";
  return (value / (1024 * 1024)).toFixed(1) + " MB";
}

export function IncidentTimeline({ incidentId, canOperate }: { incidentId: number; canOperate: boolean }) {
  const [events, setEvents] = useState<IncidentTimelineEvent[]>([]);
  const [attachments, setAttachments] = useState<IncidentEvidenceAttachment[]>([]);
  const [note, setNote] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function refresh() {
    const timeline = await getIncidentTimeline(incidentId);
    setEvents(timeline.events);
    if (canOperate) {
      const evidence = await getIncidentAttachments(incidentId);
      setAttachments(evidence.items);
    } else {
      setAttachments([]);
    }
  }

  useEffect(() => {
    let active = true;
    Promise.all([
      getIncidentTimeline(incidentId),
      canOperate ? getIncidentAttachments(incidentId) : Promise.resolve({items: [] as IncidentEvidenceAttachment[]}),
    ]).then(([timeline, evidence]) => {
      if (active) { setEvents(timeline.events); setAttachments(evidence.items); setError(""); }
    }).catch((reason: unknown) => {
      if (active) setError(reason instanceof Error ? reason.message : "Investigation evidence could not be loaded.");
    });
    return () => { active = false; };
  }, [incidentId, canOperate]);

  async function submitNote(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!note.trim()) return;
    setBusy(true); setError("");
    try { await addIncidentNote(incidentId, note.trim()); setNote(""); await refresh(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Note could not be saved."); }
    finally { setBusy(false); }
  }

  async function uploadFile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedFile) return;
    setBusy(true); setError("");
    try {
      await uploadIncidentAttachment(incidentId, selectedFile);
      setSelectedFile(null);
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Evidence attachment could not be uploaded.");
    } finally { setBusy(false); }
  }

  async function exportEvidence() {
    setBusy(true); setError("");
    try { await downloadIncidentEvidence(incidentId); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Evidence export failed."); }
    finally { setBusy(false); }
  }

  async function downloadAttachment(item: IncidentEvidenceAttachment) {
    setBusy(true); setError("");
    try { await downloadIncidentAttachment(incidentId, item); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Attachment download failed."); }
    finally { setBusy(false); }
  }

  return <section className="incident-timeline">
    <div className="panel-heading"><div><p className="eyebrow">PROVENANCE-AWARE RECORD</p><h4>Investigation timeline</h4></div>
      {canOperate && <button className="secondary-button compact" disabled={busy} onClick={() => void exportEvidence()}>Export redacted evidence</button>}
    </div>
    {error && <div className="inline-error" role="alert">{error}</div>}
    {canOperate && <>
      <form className="timeline-note-form" onSubmit={submitNote}>
        <label htmlFor={"incident-note-" + incidentId}>Add analyst note</label>
        <textarea id={"incident-note-" + incidentId} value={note} onChange={(event) => setNote(event.target.value)} maxLength={5000} rows={3} placeholder="Record an observation, decision or next step…" />
        <button className="primary-button compact" type="submit" disabled={busy || !note.trim()}>{busy ? "Saving…" : "Add note"}</button>
      </form>
      <form className="timeline-note-form evidence-upload-form" onSubmit={uploadFile}>
        <label htmlFor={"incident-evidence-" + incidentId}>Attach evidence (PDF, PNG, JPEG or UTF-8 text; server limit applies)</label>
        <input key={incidentId + "-" + (selectedFile ? selectedFile.name : "empty")} id={"incident-evidence-" + incidentId} type="file" accept=".pdf,.png,.jpg,.jpeg,.txt,.log,.csv" disabled={busy}
          onChange={(event: ChangeEvent<HTMLInputElement>) => setSelectedFile(event.target.files?.[0] ?? null)} />
        <button className="secondary-button compact" type="submit" disabled={busy || !selectedFile}>{busy ? "Working…" : "Upload evidence"}</button>
      </form>
      <div className="timeline-attachments">
        <div className="panel-heading"><h4>Evidence attachments</h4><small>{attachments.length} / 100</small></div>
        {attachments.length ? <ul>{attachments.map((item) => <li key={item.id}>
          <div><strong>{item.filename}</strong><small>{item.media_type} · {sizeLabel(item.size_bytes)} · SHA-256 {item.sha256.slice(0, 12)}…</small><small>Expires {dateLabel(item.expires_at)}</small></div>
          <button className="secondary-button compact" disabled={busy} onClick={() => void downloadAttachment(item)}>Verify &amp; download</button>
        </li>)}</ul> : <p className="integration-note">No active evidence attachments. Uploads are access-controlled and expire under the configured retention policy.</p>}
      </div>
    </>}
    {events.length ? <ol className="timeline-list">{events.map((item) => <li key={item.id}>
      <span className="timeline-marker" />
      <div className="timeline-event"><div className="timeline-event-head"><strong>{item.type.split(".").join(" · ")}</strong><time>{dateLabel(item.occurred_at)}</time></div>
        <p>{item.summary}</p><small>Provenance: {item.provenance}{item.actor_user_id ? " · User " + item.actor_user_id : ""}</small>
        {Object.keys(item.details).length > 0 && <pre>{JSON.stringify(item.details, null, 2)}</pre>}
      </div>
    </li>)}</ol> : <div className="empty-state"><strong>No timeline events available</strong><p>Incident changes, source findings, detections and analyst notes will appear here.</p></div>}
    <p className="integration-note">Evidence files are stored outside the web root, downloaded as attachments, checked against their SHA-256 digest, and never included in the JSON export. The digest is an integrity check, not a tamper-proof chain of custody.</p>
  </section>;
}
