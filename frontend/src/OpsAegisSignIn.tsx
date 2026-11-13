"use client";

import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { bootstrapFirstAdmin, getAuthSetupStatus } from "./api";
import { MetallicButton } from "./components/ui/metallic-button";
import SculptureHero from "./components/ui/liquid-sculpture-hero";
import "./OpsAegisSignIn.css";

type ThemePreference = "dark" | "light" | "system";

interface OpsAegisSignInProps {
  onLogin: (email: string, password: string) => Promise<void>;
  theme: ThemePreference;
  onThemeChange: (value: ThemePreference) => void;
}

export function OpsAegisSignIn({ onLogin }: OpsAegisSignInProps) {
  const [mode, setMode] = useState<"sign-in" | "sign-up" | "setup">("sign-in");
  const [showAuth, setShowAuth] = useState(false);
  const [setupToken, setSetupToken] = useState("");
  const [setupRequired, setSetupRequired] = useState(false);
  const [setupEnabled, setSetupEnabled] = useState(false);
  useEffect(() => { getAuthSetupStatus().then(status => { setSetupRequired(status.setup_required); setSetupEnabled(status.setup_enabled); if (status.setup_required && status.setup_enabled) setMode("setup"); }).catch(() => setError("Cannot verify initial setup status. Check the API connection.")); }, []);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setError("");
    setBusy(true);
    try {
      if (mode === "setup") {
        if (!setupToken) throw new Error("Enter the one-time setup token configured by the deployment administrator.");
        await bootstrapFirstAdmin(email.trim(), password, setupToken);
        setSetupToken(""); setSetupRequired(false); setMode("sign-in");
        setError("");
      } else { await onLogin(email.trim(), password); }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Sign-in failed. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <SculptureHero
        brand="OpsAegis"
        navLinks={[{ label: "Platform", href: "#platform" }, { label: "Security", href: "#security" }, { label: "Intelligence", href: "#intelligence" }, { label: "About", href: "#about" }]}
        navCta={{ label: "Contact", href: "mailto:security@opsaegis.local" }}
        eyebrow="SECURITY OPERATIONS — BUILT FOR RESILIENCE"
        headline={"Clarity in\nevery signal."}
        headlineAccent="every signal."
        body="See threats sooner. Respond with confidence. Keep every operation in control."
        primaryCta={{ label: "Login Now", href: "#login" }}
        secondaryCta={undefined}
        backdropText="OPSAEGIS"
        showCredit={false}
        background="#F0EEEA"
        imageBackground="#EAE9E7"
        sculptureScale={1.02}
        onPrimaryCtaClick={() => setShowAuth(true)}
      />
      {showAuth && <div className="oa-login-overlay" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setShowAuth(false); }}>
        <div className="oa-login-dialog" role="dialog" aria-modal="true" aria-label="OpsAegis sign in">
          <button className="oa-login-close" type="button" aria-label="Close sign in" onClick={() => setShowAuth(false)}>×</button>
          <main className="oa-auth oa-auth-modal">
      <section className="oa-auth-main">
        <header className="oa-auth-header">
          <a className="oa-auth-brand" href="/" aria-label="OpsAegis home">
            <span className="oa-auth-mark">OA</span>
            <span><strong>OpsAegis</strong><small>SECURITY OPERATIONS</small></span>
          </a>
          <span className="oa-help">Need help?</span>
        </header>

        <div className="oa-auth-content">
          <div className="oa-auth-card">
            <div className="oa-auth-tabs" role="tablist" aria-label="Account access">
              <button type="button" role="tab" aria-selected={mode === "sign-in"} className={mode === "sign-in" ? "active" : ""} onClick={() => { setMode("sign-in"); setError(""); }}>Sign in</button>
              <button type="button" role="tab" aria-selected={mode === "sign-up"} className={mode === "sign-up" ? "active" : ""} onClick={() => { setMode("sign-up"); setError(""); }}>Request access</button>
            </div>

            {mode === "setup" ? (
              <>
                <p className="oa-eyebrow">INITIAL WORKSPACE SETUP</p><h1>Create administrator.</h1>
                <p className="oa-auth-copy">No accounts exist yet. Use the one-time setup token configured by your deployment administrator to create the first administrator.</p>
                <form className="oa-auth-form" onSubmit={submit}>
                  <label htmlFor="oa-email">Administrator email</label><input id="oa-email" type="email" required maxLength={320} value={email} onChange={e=>setEmail(e.target.value)} autoComplete="email"/>
                  <label htmlFor="oa-password">Password (minimum 12 characters)</label><input id="oa-password" type="password" required minLength={12} maxLength={128} value={password} onChange={e=>setPassword(e.target.value)} autoComplete="new-password"/>
                  <label htmlFor="oa-setup-token">One-time setup token</label><input id="oa-setup-token" type="password" required value={setupToken} onChange={e=>setSetupToken(e.target.value)} autoComplete="off"/>
                  {error && <div className="oa-auth-error" role="alert">{error}</div>}
                  <MetallicButton className="oa-submit" type="submit" disabled={busy}>{busy ? "Creating administrator…" : "Initialize secure workspace"} <span aria-hidden="true">→</span></MetallicButton>
                </form>
              </>
            ) : mode === "sign-in" ? (
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
                  {error && <div className="oa-auth-error" role="alert">{error}</div>}
                  <MetallicButton className="oa-submit" type="submit" disabled={busy}>{busy ? "Authenticating…" : "Sign in"} <span aria-hidden="true">→</span></MetallicButton>
                </form>
                <p className="oa-auth-note"><span aria-hidden="true">▣</span> Protected by OpsAegis API authentication · Session-scoped access</p>
              </>
            ) : (
              <div className="oa-provision">
                <p className="oa-eyebrow">ACCOUNT PROVISIONING</p>
                <h1>Request access.</h1>
                <p className="oa-auth-copy">OpsAegis accounts are created by an authorized administrator. This prevents untrusted users from registering themselves into your security operations workspace.</p>
                {setupRequired && !setupEnabled && <div className="oa-auth-error">Initial setup is not enabled. Set OPS_AEGIS_BOOTSTRAP_TOKEN on the API service, then reload this page.</div>}
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
        </div>
      </div>}
    </>
  );
}

export default OpsAegisSignIn;
