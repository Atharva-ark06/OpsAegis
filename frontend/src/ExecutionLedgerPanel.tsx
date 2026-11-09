import { useEffect, useState } from "react";
import {
  getPlaybookExecutions,
  PlaybookExecutionRecord,
  PlaybookExecutionStatus,
} from "./api";

const STATUS_OPTIONS: { value: "all" | PlaybookExecutionStatus; label: string }[] = [
  { value: "all", label: "All statuses" },
  { value: "pending", label: "Pending" },
  { value: "claimed", label: "Claimed" },
  { value: "executing", label: "Executing" },
  { value: "succeeded", label: "Succeeded" },
  { value: "failed", label: "Failed" },
  { value: "outcome_unknown", label: "Outcome unknown" },
];

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
        <p className="eyebrow">PHASE 6.3 · RESPONSE GOVERNANCE</p>
        <h3>Playbook execution ledger</h3>
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
      <strong>Execution disabled.</strong> This panel reads persisted ledger records only. It cannot start, retry, cancel, isolate, or compensate an action.
    </div>

    {error && <p className="trend-error" role="alert">{error}</p>}
    {loading && <p className="trend-note">Loading execution records…</p>}
    {!loading && !error && items.length === 0 && <div className="trend-empty">No execution records match this filter.</div>}

    {items.length > 0 && <div className="execution-ledger-list">
      {items.map((item) => <article className="execution-ledger-row" key={item.id}>
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
      </article>)}
    </div>}

    {hasMore && !error && <div className="execution-ledger-more">
      <button className="primary-button compact" type="button" disabled={loadingMore} onClick={() => setOffset((value) => value + 25)}>
        {loadingMore ? "Loading…" : "Load more records"}
      </button>
    </div>}
    <p className="execution-ledger-footnote">Sensitive target identifiers, parameter hashes, idempotency keys and provider references are intentionally not displayed.</p>
  </section>;
}
