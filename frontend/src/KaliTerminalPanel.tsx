import { useEffect, useState } from "react";
import {
  createKaliTerminalSession,
  getKaliTerminalHealth,
  KaliTerminalHealth,
  revokeKaliTerminalSession,
} from "./api";

export function KaliTerminalPanel({ canAccess }: { canAccess: boolean }) {
  const [health, setHealth] = useState<KaliTerminalHealth | null>(null);
  const [busy, setBusy] = useState(false);
  const [active, setActive] = useState(false);
  const [frameKey, setFrameKey] = useState(0);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function refresh() {
    setError("");
    try {
      setHealth(await getKaliTerminalHealth());
    } catch (reason) {
      setHealth(null);
      setError(reason instanceof Error ? reason.message : "Unable to check the Kali terminal.");
    }
  }

  useEffect(() => {
    if (canAccess) void refresh();
  }, [canAccess]);

  async function launch() {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await createKaliTerminalSession();
      setFrameKey(value => value + 1);
      setActive(true);
      setNotice("A five-minute authenticated terminal session has been issued.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to start the Kali terminal.");
      setActive(false);
    } finally {
      setBusy(false);
    }
  }

  async function stop() {
    setBusy(true);
    setError("");
    try {
      await revokeKaliTerminalSession();
      setNotice("Terminal session cookie revoked.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to revoke the terminal session.");
    } finally {
      setActive(false);
      setBusy(false);
    }
  }

  if (!canAccess) return null;

  return (
    <section className="kali-terminal-workspace">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">TEAM SECURITY WORKSPACE</p>
          <h3>Kali Linux web terminal</h3>
        </div>
        <span className={"engine-status " + (health?.status || "unknown")}>
          {health?.status === "healthy" ? "Terminal ready" : health?.status === "unhealthy" ? "Terminal unavailable" : "Terminal not configured"}
        </span>
      </div>
      <p className="integration-note">
        Browser-based Kali Rolling shell. Access is limited to active administrators and analysts.
        Each session requires a short-lived OpsAegis authorization cookie.
      </p>
      {error && <div className="error-banner" role="alert">{error}</div>}
      {notice && <div className="success-banner" role="status">{notice}</div>}
      <div className="kali-terminal-actions">
        {!active ? (
          <button className="primary-button compact" onClick={() => void launch()} disabled={busy || !health?.execution_enabled}>
            {busy ? "Starting terminal…" : "Launch Kali terminal"}
          </button>
        ) : (
          <>
            <button className="primary-button compact" onClick={() => void launch()} disabled={busy}>
              {busy ? "Renewing…" : "Renew session"}
            </button>
            <button className="secondary-button" onClick={() => void stop()} disabled={busy}>Close terminal</button>
          </>
        )}
        <button className="secondary-button" onClick={() => void refresh()} disabled={busy}>Refresh status</button>
        <span className="kali-terminal-meta">{active ? "Authenticated session · expires after 5 minutes" : "Session not started"}</span>
      </div>
      {active && (
        <iframe
          key={frameKey}
          className="kali-terminal-frame"
          title="OpsAegis Kali Linux terminal"
          src="/terminal/"
          referrerPolicy="no-referrer"
          allow="clipboard-read; clipboard-write"
        />
      )}
      <p className="kali-terminal-note">
        Shared team environment: shell processes are separate, but team members use the same Kali container
        and persistent /workspace files. Do not store personal credentials, private keys or unrelated sensitive data.
        Use this shell only for systems and labs your team is explicitly authorized to test.
      </p>
    </section>
  );
}
