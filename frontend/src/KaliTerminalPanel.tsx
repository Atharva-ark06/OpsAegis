const KALI_TERMINAL_URL = (import.meta.env.VITE_KALI_TERMINAL_URL || "").trim();

export function KaliTerminalPanel({ canAccess }: { canAccess: boolean }) {
  if (!canAccess) return null;
  const configured = /^https:\/\//i.test(KALI_TERMINAL_URL);

  return (
    <section className="kali-terminal-workspace">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">TEAM SECURITY WORKSPACE</p>
          <h3>Kali Linux web terminal</h3>
        </div>
        <span className={"engine-status " + (configured ? "healthy" : "unknown")}>
          {configured ? "Terminal link configured" : "Terminal URL required"}
        </span>
      </div>
      <p className="integration-note">
        Open the team's hosted Kali Rolling terminal in a separate tab. The Railway terminal's HTTP Basic
        Authentication prompt protects access; use the team credentials stored in Railway, never in OpsAegis.
      </p>
      <div className="kali-terminal-actions">
        <a className="primary-button compact" href={configured ? KALI_TERMINAL_URL : "https://railway.com/project/313791b3-2048-4a41-9d0f-5590eaee75a5"} target="_blank" rel="noopener noreferrer"
          aria-disabled={!configured} onClick={(event) => { if (!configured) event.preventDefault(); }}>
          {configured ? "Open Kali web terminal ↗" : "Configure Kali terminal in Railway ↗"}
        </a>
        <span className="kali-terminal-meta">{configured ? "Opens in a new tab · Basic Auth protected" : "Set VITE_KALI_TERMINAL_URL on the frontend service after deployment"}</span>
      </div>
      <p className="kali-terminal-note">
        The template uses a shared team username/password and persistent /data storage. Keep the credentials
        in Railway variables, rotate them periodically, and use the terminal only for authorized labs and systems.
      </p>
    </section>
  );
}
