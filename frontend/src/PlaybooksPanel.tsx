import { useEffect, useState } from "react";
import { useLiveRefresh } from "./live-refresh";
import { PlaybookWorkflowDesigner } from "./components/ui/playbook-workflow-designer";
import {
  createPlaybookApproval, decidePlaybookApproval, getPlaybookActions,
  getPlaybookApprovals, getPlaybooks, previewPlaybook,
} from "./api";
import type {
  Incident, PlaybookAction, PlaybookApproval, PlaybookApprovalStatus,
  PlaybookDefinition, PlaybookPreview, User,
} from "./api";

function dateLabel(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

const FILTERS: {value: PlaybookApprovalStatus | "all"; label: string}[] = [
  {value:"pending",label:"Pending"},
  {value:"approved",label:"Approved"},
  {value:"rejected",label:"Rejected"},
  {value:"expired",label:"Expired"},
  {value:"all",label:"All"},
];

export function PlaybooksPanel({incidents,user}: {incidents:Incident[];user:User}) {
  const [playbooks,setPlaybooks] = useState<PlaybookDefinition[]>([]);
  const [actions,setActions] = useState<PlaybookAction[]>([]);
  const [approvals,setApprovals] = useState<PlaybookApproval[]>([]);
  const [filter,setFilter] = useState<PlaybookApprovalStatus | "all">("pending");
  const [incidentId,setIncidentId] = useState("");
  const [lookback,setLookback] = useState("60");
  const [requestReason,setRequestReason] = useState("");
  const [decisionReasons,setDecisionReasons] = useState<Record<number,string>>({});
  const [preview,setPreview] = useState<PlaybookPreview|null>(null);
  const [loading,setLoading] = useState(true);
  const [busy,setBusy] = useState<string|null>(null);
  const [error,setError] = useState("");
  const [message,setMessage] = useState("");

  useEffect(() => {
    if (!incidentId && incidents.length) setIncidentId(String(incidents[0].id));
  },[incidents,incidentId]);

  async function loadApprovals(nextFilter=filter) {
    const result = await getPlaybookApprovals(nextFilter);
    setApprovals(result.items);
  }

  useLiveRefresh(async () => {
    const [catalogue, actionResult, approvalResult] = await Promise.all([getPlaybooks(), getPlaybookActions("incident-investigation"), getPlaybookApprovals(filter)]);
    setPlaybooks(catalogue.items); setActions(actionResult.items); setApprovals(approvalResult.items);
  }, { intervalMs: 15000 });

  useEffect(() => {
    let active = true;
    setLoading(true);
    Promise.all([getPlaybooks(),getPlaybookActions("incident-investigation"),getPlaybookApprovals(filter)])
      .then(([catalogue,actionResult,approvalResult]) => {
        if (!active) return;
        setPlaybooks(catalogue.items);
        setActions(actionResult.items);
        setApprovals(approvalResult.items);
        setError("");
      })
      .catch((reason:unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : "Playbook workspace could not be loaded.");
      })
      .finally(() => {if(active)setLoading(false);});
    return () => {active=false;};
  },[filter]);

  async function runPreview() {
    const id=Number(incidentId), minutes=Number(lookback);
    if (!Number.isSafeInteger(id)||id<1||!Number.isInteger(minutes)||minutes<5||minutes>1440) {
      setError("Select an incident and a lookback between 5 and 1,440 minutes."); return;
    }
    setBusy("preview");setError("");setMessage("");setPreview(null);
    try {
      const result=await previewPlaybook("incident-investigation",{incident_id:id,lookback_minutes:minutes});
      setPreview(result);setMessage("Read-only investigation preview generated. No action was executed.");
    } catch(reason) {setError(reason instanceof Error?reason.message:"Preview failed.");}
    finally {setBusy(null);}
  }

  async function requestApproval() {
    const id=Number(incidentId), minutes=Number(lookback);
    if (!Number.isSafeInteger(id)||id<1||!Number.isInteger(minutes)||minutes<5||minutes>1440||requestReason.trim().length<10) {
      setError("Select an incident, a valid lookback, and a reason of at least 10 characters.");return;
    }
    setBusy("request");setError("");setMessage("");
    try {
      const item=await createPlaybookApproval("incident-investigation",{incident_id:id,lookback_minutes:minutes,reason:requestReason.trim()});
      setRequestReason("");setMessage("Approval request #"+item.id+" created. A different operator must review it.");
      setFilter("pending");
      await loadApprovals("pending");
    } catch(reason) {setError(reason instanceof Error?reason.message:"Approval request failed.");}
    finally {setBusy(null);}
  }

  async function decide(item:PlaybookApproval,decision:"approve"|"reject") {
    const reason=(decisionReasons[item.id]||"").trim();
    if(reason.length<5){setError("Enter a decision reason of at least 5 characters.");return;}
    setBusy("decision-"+item.id);setError("");setMessage("");
    try {
      await decidePlaybookApproval(item.id,{decision,reason});
      setDecisionReasons(current=>({...current,[item.id]:""}));
      setMessage("Approval request #"+item.id+" "+(decision==="approve"?"approved":"rejected")+". This records governance only; it does not execute an action.");
      await loadApprovals(filter);
    } catch(reasonError) {setError(reasonError instanceof Error?reasonError.message:"Approval decision failed.");}
    finally {setBusy(null);}
  }

  return <div className="playbooks-workspace">
    <PlaybookWorkflowDesigner />
    {error && <div className="inline-error" role="alert">{error}</div>}
    {message && <div className="success-banner" role="status">{message}</div>}
    <section className="panel playbook-catalogue">
      <div className="panel-heading"><div><p className="eyebrow">PHASE 6.3 · GOVERNED WORKFLOWS</p><h3>Playbook catalogue</h3></div><span className="tag">Dry-run only</span></div>
      {loading ? <p className="integration-note">Loading playbooks and approvals…</p> : playbooks.length ? playbooks.map(item=><article className="playbook-definition" key={item.id}>
        <div><h4>{item.name} <small>v{item.version}</small></h4><p>{item.description}</p></div>
        <ul>{item.preconditions.map((condition,index)=><li key={index}>{condition}</li>)}</ul>
        <p className="integration-note">External actions: disabled · Execution mode: {item.execution_mode}</p>
      </article>) : <p className="integration-note">No playbooks are registered.</p>}
      <div className="playbook-action-catalogue"><h4>Action contracts</h4>
        {actions.map(action=><div className="playbook-action-row" key={action.action_id}>
          <div><strong>{action.action_id}</strong><small>{action.description}</small><small>Independent approval required · compensation: {action.compensation_action_id}</small></div>
          <span className="tag">{action.execution_available?"Available":"Disabled / no adapter"}</span>
        </div>)}
        <p className="integration-note">No provider adapter is registered. The action catalogue is descriptive and cannot issue Wazuh isolation or unisolation requests.</p>
      </div>
    </section>

    <section className="panel playbook-preview-panel">
      <div className="panel-heading"><div><p className="eyebrow">READ-ONLY INVESTIGATION</p><h3>Prepare an investigation</h3></div></div>
      <div className="playbook-form-grid">
        <label>Incident<select value={incidentId} onChange={event=>{setIncidentId(event.target.value);setPreview(null);}} disabled={!incidents.length}>
          <option value="">Select an incident</option>
          {incidents.map(item=><option key={item.id} value={item.id}>INCIDENT-{item.id} · {item.title} ({item.status})</option>)}
        </select></label>
        <label>Lookback (minutes)<input type="number" min="5" max="1440" value={lookback} onChange={event=>setLookback(event.target.value)}/></label>
      </div>
      {!incidents.length && <p className="integration-note">No incidents are currently loaded. Create or ingest an incident before preparing a playbook.</p>}
      <div className="playbook-controls">
        <button className="primary-button compact" type="button" disabled={busy!==null||!incidentId} onClick={()=>void runPreview()}>{busy==="preview"?"Preparing…":"Generate dry-run preview"}</button>
      </div>
      {preview && <div className="playbook-preview-result">
        <div className="panel-heading"><h4>{preview.incident.title}</h4><span className="tag">Preview only · not executed</span></div>
        <p>{preview.incident.severity.toUpperCase()} · {preview.incident.status} · {preview.playbook_id} v{preview.playbook_version}</p>
        <div className="playbook-preview-stats"><span><strong>{preview.observed_context.detections_in_window}</strong> detections</span><span><strong>{preview.observed_context.linked_findings}</strong> linked findings</span><span><strong>{preview.observed_context.affected_asset_ids.length}</strong> affected assets</span></div>
        <h4>Proposed analyst checklist</h4><ol>{preview.proposed_checklist.map((step,index)=><li key={index}>{step}</li>)}</ol>
        {preview.observed_context.possible_truncation&&<p className="inline-error">Context limits were reached; this preview may be incomplete.</p>}
        <p className="integration-note">No side effects: {preview.side_effects.length===0?"confirmed":preview.side_effects.join(", ")}. {preview.limitations.join(" ")}</p>
      </div>}
      <div className="playbook-approval-request">
        <label>Reason for independent review<textarea value={requestReason} maxLength={1000} rows={3} onChange={event=>setRequestReason(event.target.value)} placeholder="Explain why another operator should review this investigation proposal…"/></label>
        <button className="secondary-button compact" type="button" disabled={busy!==null||!incidentId||requestReason.trim().length<10} onClick={()=>void requestApproval()}>{busy==="request"?"Submitting…":"Request independent approval"}</button>
      </div>
    </section>

    <section className="panel playbook-approvals">
      <div className="panel-heading"><div><p className="eyebrow">SEPARATION OF DUTIES</p><h3>Approval queue</h3></div>
        <label>Filter<select value={filter} onChange={event=>setFilter(event.target.value as PlaybookApprovalStatus|"all")}>{FILTERS.map(option=><option key={option.value} value={option.value}>{option.label}</option>)}</select></label>
      </div>
      {approvals.length? <div className="playbook-approval-list">{approvals.map(item=>{
        const selfRequested=item.requested_by_user_id===user.id;
        const pending=item.status==="pending";
        return <article className="playbook-approval-card" key={item.id}>
          <div className="playbook-approval-heading"><div><strong>Approval #{item.id} · Incident #{item.incident_id}</strong><small>{item.playbook_id} v{item.playbook_version} · requested {dateLabel(item.created_at)}</small></div><span className="tag">{item.status}</span></div>
          <p>{item.request_reason}</p>
          <small>Requested by user {item.requested_by_user_id} · Expires {dateLabel(item.expires_at)}</small>
          {item.decision_reason&&<p className="integration-note">Decision: {item.decision_reason}</p>}
          {pending&&<div className="playbook-decision">
            {selfRequested?<p className="integration-note">You requested this item. A different active operator must review it.</p>:<>
              <label>Decision reason<textarea rows={2} maxLength={1000} value={decisionReasons[item.id]||""} onChange={event=>setDecisionReasons(current=>({...current,[item.id]:event.target.value}))} placeholder="Record the basis for approval or rejection…"/></label>
              <div className="playbook-controls">
                <button className="primary-button compact" type="button" disabled={busy!==null||(decisionReasons[item.id]||"").trim().length<5} onClick={()=>void decide(item,"approve")}>Approve request</button>
                <button className="secondary-button compact" type="button" disabled={busy!==null||(decisionReasons[item.id]||"").trim().length<5} onClick={()=>void decide(item,"reject")}>Reject request</button>
              </div>
            </>}
          </div>}
          {item.reviewed_by_user_id!==null&&<small>Reviewed by user {item.reviewed_by_user_id} · {dateLabel(item.reviewed_at)}</small>}
        </article>;
      })}</div>:<div className="empty-state"><strong>No {filter==="all"?"approval":filter} requests</strong><p>Approval records will appear here when an operator requests an independent review.</p></div>}
      <p className="integration-note">Approval is a governance record only. It does not dispatch playbooks, execute provider actions or enable response integrations. A request cannot be approved by its requester.</p>
    </section>
  </div>;
}
