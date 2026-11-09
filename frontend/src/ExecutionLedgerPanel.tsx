import { useEffect, useState } from "react";
import {
  getPlaybookExecutions,
  PlaybookExecutionRecord,
  PlaybookExecutionStatus,
} from "./api";
import "./recovery-guidance.css";

const STATUS_OPTIONS: { value: "all" | PlaybookExecutionStatus; label: string }[] = [
  { value: "all", label: "All statuses" },
  { value: "pending", label: "Pending" },
  { value: "claimed", label: "Claimed" },
  { value: "executing", label: "Executing" },
  { value: "succeeded", label: "Succeeded" },
  { value: "failed", label: "Failed" },
  { value: "outcome_unknown", label: "Outcome unknown" },
];

const RECOVERY_GUIDANCE: Record<PlaybookExecutionRecord["recovery_guidance"], { title: string; detail: string; tone: string }> = {
  not_applicable: {
    title: "No recovery step indicated",
    detail: "This ledger state does not indicate a completed provider action. Do not infer that isolation or recovery occurred.",
    tone: "neutral",
  },
  separate_approval_required: {
    title: "Separate approval required",
    detail: "If unisolation is needed, obtain a distinct approval for the exact target and verify provider state independently. No automatic compensation is available.",
    tone: "caution",
  },
  verify_provider_state: {
    title: "Verify provider state",
    detail: "A failed request does not prove that no side effect occurred. Check the authorized provider state before deciding on recovery.",
    tone: "caution",
  },
  reconcile_provider_state: {
    title: "Outcome unknown — stop and reconcile",
    detail: "Do not retry or assume success/failure. Use an authorized read-only provider-state check; keep the outcome unknown if it cannot be confirmed.",
    tone: "warning",
  },
  operator_review_required: {
    title: "Operator review required",
    detail: "The ledger records a compensation state, but this repository has no dispatcher. Do not infer that a provider request was sent or completed.",
    tone: "caution",
  },
  verify_unisolated_state: {
    title: "Independently verify unisolation",
    detail: "A succeeded ledger state is not proof of restored endpoint connectivity. Confirm the provider's unisolated state before closing recovery.",
    tone: "caution",
  },
  manual_recovery_required: {
    title: "Manual recovery required",
    detail: "Stop automatic retries. Reconcile the actual provider state, preserve the audit trail and escalate through the approved operator process.",
    tone: "warning",
  },
};

function formatTimestamp(value: string | null): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Invalid timestamp" : date.toLocaleString();
}

function statusLabel(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function ExecutionLedgerPanel({ refreshKey }: { refreshKey: number }) {
  const [status, setStatus] = useState<"all" | PlaybookExecutionStatus>("all");
  const [items, setItems] = useState<PlaybookExecutionRecord[]>([]);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    setItems([]);
    setOffset(0);
    setHasMore(false);
  }, [refreshKey]);

  useEffect(() => {
    let active = true;
    const pageOffset = offset;
    if (pageOffset === 0) setLoading(true);
    else setLoadingMore(true);
    setError("");

    getPlaybookExecutions({
      status: status === "all" ? undefined : status,
      limit: 25,
      offset: pageOffset,
    }).then((page) => {
      if (!active) return;
      setItems((current) => pageOffset === 0 ? page.items : [...current, ...page.items]);
      setHasMore(page.has_more);
    }).catch((reason: unknown) => {
      if (active) setError(reason instanceof Error ? reason.message : "Execution ledger could not be loaded.");
    }).finally(() => {
      if (active) { setLoading(false); setLoadingMore(false); }
    });

    return () => { active = false; };
  }, [status, offset, refreshKey, reloadKey]);

  function changeStatus(value: "all" | PlaybookExecutionStatus) {
    setItems([]);
    setOffset(0);
    setStatus(value);
  }

  function refresh() {
    setItems([]);
    setOffset(0);
    setReloadKey((value) => value + 1);
  }

  return <section className="panel execution-ledger-panel">
    <div className="panel-heading">
      <div>
        <p className="eyebrow">PHASE 6 · RESPONSE GOVERNANCE</p>
        <h3>Execution & recovery ledger</h3>
        <p className="execution-ledger-subtitle">Read-only lifecycle visibility · latest 25 records per page</p>
      </div>
      <div className="execution-ledger-controls">
        <label>STATUS
          <select aria-label="Filter execution status" value={status} onChange={(event) => changeStatus(event.target.value as "all" | PlaybookExecutionStatus)}>
            {STATUS_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </select>
        </label>
        <button className="text-button" type="button" onClick={refresh} disabled={loading || loadingMore}>Refresh ↻</button>
      </div>
    </div>

    <div className="execution-ledger-safety" role="note">
      <strong>Provider actions disabled.</strong> This panel reads persisted ledger records and conservative recovery guidance only. It cannot start, retry, cancel, isolate, unisolate, or compensate an action.
    </div>

    <div className="recovery-validation-banner" role="note">
      <div>
        <strong>Staging validation: not evidenced here</strong>
        <p>Live Wazuh isolation/unisolation, provider-state verification and rollback have not been validated by this dashboard. Follow the operator runbook and record independently reviewed, sanitized evidence.</p>
      </div>
      <a href="https://github.com/Atharva-ark06/OpsAegis/blob/main/docs/PHASE6_RECOVERY_STAGING.md" target="_blank" rel="noreferrer">Open staging runbook ↗</a>
    </div>

    {error && <p className="trend-error" role="alert">{error}</p>}
    {loading && <p className="trend-note">Loading execution records…</p>}
    {!loading && !error && items.length === 0 && <div className="trend-empty">No execution records match this filter.</div>}

    {items.length > 0 && <div className="execution-ledger-list">
      {items.map((item) => {
        const guidance = RECOVERY_GUIDANCE[item.recovery_guidance] ?? RECOVERY_GUIDANCE.manual_recovery_required;
        return <article className="execution-ledger-row" key={item.id}>
          <div className="execution-ledger-main">
            <div className="execution-ledger-title">
              <strong>{item.action_id}</strong>
              <span className={"execution-state state-" + item.status}>{statusLabel(item.status)}</span>
            </div>
            <small>Execution #{item.id} · Approval #{item.approval_id} · v{item.action_version}</small>
          </div>
          <div className="execution-ledger-compensation">
            <span>COMPENSATION</span>
            <strong className={"execution-state state-" + item.compensation_status}>{statusLabel(item.compensation_status)}</strong>
          </div>
          <div className="execution-ledger-times">
            <span>Created {formatTimestamp(item.created_at)}</span>
            <span>Started {formatTimestamp(item.started_at)}</span>
            <span>Completed {formatTimestamp(item.completed_at)}</span>
          </div>
          <div className={"execution-recovery-guidance guidance-" + guidance.tone}>
            <strong>{guidance.title}</strong>
            <p>{guidance.detail}</p>
          </div>
        </article>;
      })}
    </div>}

    {hasMore && !error && <div className="execution-ledger-more">
      <button className="primary-button compact" type="button" disabled={loadingMore} onClick={() => setOffset((value) => value + 25)}>
        {loadingMore ? "Loading…" : "Load more records"}
      </button>
    </div>}
    <p className="execution-ledger-footnote">Sensitive target identifiers, parameter hashes, idempotency keys and provider references are intentionally not displayed. A ledger status is not independent proof of provider state.</p>
  </section>;
}
