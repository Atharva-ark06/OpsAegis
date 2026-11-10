"use client";

import { FormEvent, useState } from "react";

type ThemePreference = "dark" | "light" | "system";

interface OpsAegisSignInProps {
  onLogin: (email: string, password: string) => Promise<void>;
  theme: ThemePreference;
  onThemeChange: (value: ThemePreference) => void;
}

export function OpsAegisSignIn({ onLogin }: OpsAegisSignInProps) {
  const [mode, setMode] = useState<"sign-in" | "sign-up">("sign-in");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [remember, setRemember] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setError("");
    setBusy(true);
    try {
      await onLogin(email.trim(), password);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Sign-in failed. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="oa-auth">
      <section className="oa-auth-main">
        <header className="oa-auth-header">
          <a className="oa-auth-brand" href="/" aria-label="OpsAegis home">
            <span className="oa-auth-mark">OA</span>
            <span><strong>OpsAegis</strong><small>SECURITY OPERATIONS</small></span>
          </a>
          <a className="oa-help" href="mailto:support@opsaegis.local">Need help?</a>
        </header>

        <div className="oa-auth-content">
          <div className="oa-auth-card">
            <div className="oa-auth-tabs" role="tablist" aria-label="Account access">
              <button type="button" role="tab" aria-selected={mode === "sign-in"} className={mode === "sign-in" ? "active" : ""} onClick={() => { setMode("sign-in"); setError(""); }}>Sign in</button>
              <button type="button" role="tab" aria-selected={mode === "sign-up"} className={mode === "sign-up" ? "active" : ""} onClick={() => { setMode("sign-up"); setError(""); }}>Create account</button>
            </div>

            {mode === "sign-in" ? (
              <>
                <p className="oa-eyebrow">SECURE OPERATIONS CONSOLE</p>
                <h1>Welcome back.</h1>
                <p className="oa-auth-copy">Sign in to monitor endpoints, investigate detections and coordinate incident response.</p>
                <div className="oa-auth-divider"><span>AUTHORIZED ACCESS</span></div>
                <form className="oa-auth-form" onSubmit={submit}>
                  <label htmlFor="oa-email">Work email</label>
                  <input id="oa-email" type="email" autoComplete="username" inputMode="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="analyst@organization.com" required maxLength={320} />
                  <div className="oa-password-label"><label htmlFor="oa-password">Password</label><span>Reset through your administrator</span></div>
                  <div className="oa-password-wrap">
                    <input id="oa-password" type={showPassword ? "text" : "password"} autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Enter your password" required maxLength={256} />
                    <button type="button" onClick={() => setShowPassword((value) => !value)} aria-label={showPassword ? "Hide password" : "Show password"}>{showPassword ? "Hide" : "Show"}</button>
                  </div>
                  <label className="oa-remember"><input type="checkbox" checked={remember} onChange={(event) => setRemember(event.target.checked)} /> Keep this session active</label>
                  {error && <div className="oa-auth-error" role="alert">{error}</div>}
                  <button className="oa-submit" type="submit" disabled={busy}>{busy ? "Authenticating…" : "Sign in"} <span aria-hidden="true">→</span></button>
                </form>
                <p className="oa-auth-note"><span aria-hidden="true">▣</span> Protected by OpsAegis API authentication · Session-scoped access</p>
              </>
            ) : (
              <div className="oa-provision">
                <p className="oa-eyebrow">ACCOUNT PROVISIONING</p>
                <h1>Request access.</h1>
                <p className="oa-auth-copy">OpsAegis accounts are created by an authorized administrator. This prevents untrusted users from registering themselves into your security operations workspace.</p>
                <div className="oa-provision-steps">
                  <span>01</span><div><strong>Contact your workspace administrator</strong><p>Ask them to provision an OpsAegis account using your work email.</p></div>
                  <span>02</span><div><strong>Receive your account details</strong><p>Your administrator assigns the appropriate role: viewer, analyst or admin.</p></div>
                  <span>03</span><div><strong>Sign in securely</strong><p>Return to this page and sign in with the credentials provided to you.</p></div>
                </div>
                <button className="oa-submit" type="button" onClick={() => setMode("sign-in")}>Back to sign in <span aria-hidden="true">→</span></button>
              </div>
            )}
          </div>
        </div>
        <footer className="oa-auth-footer"><span>© 2026 OpsAegis</span><span>Defend · Detect · Respond</span></footer>
      </section>

      <aside className="oa-auth-aside" aria-label="OpsAegis platform overview">
        <div className="oa-status-pill"><i /> Operations systems <strong>SECURE CONSOLE</strong></div>
        <div className="oa-preview">
          <div className="oa-preview-head"><span>THREAT MONITORING · LIVE VIEW</span><b>OPSAEGIS</b></div>
          <div className="oa-preview-metrics">
            <div><small>DETECTIONS</small><strong>—</strong><em>Awaiting telemetry</em></div>
            <div><small>ENDPOINTS</small><strong>—</strong><em>API-backed inventory</em></div>
          </div>
          <div className="oa-chart" aria-hidden="true"><div className="oa-chart-grid" /><svg viewBox="0 0 520 150" preserveAspectRatio="none"><path d="M0 110 C35 96 50 112 82 82 S130 105 160 66 S208 85 240 54 S285 84 320 48 S365 68 400 34 S455 60 520 18" /><path className="oa-chart-fill" d="M0 110 C35 96 50 112 82 82 S130 105 160 66 S208 85 240 54 S285 84 320 48 S365 68 400 34 S455 60 520 18 L520 150 L0 150Z" /></svg></div>
          <div className="oa-preview-legend"><span><i /> Security events</span><span>Illustrative preview · live data appears after sign-in</span></div>
        </div>
        <div className="oa-feature-list">
          <div><span>01</span><p><strong>Endpoint visibility</strong><small>Wazuh agent inventory and health</small></p></div>
          <div><span>02</span><p><strong>Threat detection</strong><small>Findings, severity and threat intelligence</small></p></div>
          <div><span>03</span><p><strong>Incident response</strong><small>Investigation timelines and playbooks</small></p></div>
        </div>
        <div className="oa-aside-caption"><span>BUILT FOR SECURITY OPERATIONS</span><strong>One workspace. Clearer signals. Faster response.</strong></div>
      </aside>
    </main>
  );
}

export default OpsAegisSignIn;
