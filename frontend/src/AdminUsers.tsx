import { FormEvent, useEffect, useState } from "react";
import { AdminUser, User, UserRole, createAdminUser, getAdminUsers, updateAdminUser } from "./api";

export function AdminUsers({ currentUser }: { currentUser: User }) {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>("viewer");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  async function refresh() { setUsers(await getAdminUsers()); }
  useEffect(() => { void refresh().catch((e: unknown) => setError(e instanceof Error ? e.message : "Unable to load users.")); }, []);
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError(""); setNotice("");
    try { await createAdminUser({ email: email.trim(), password, role }); setEmail(""); setPassword(""); setRole("viewer"); await refresh(); setNotice("Account created. Share its credentials with the user through a secure channel."); }
    catch (e) { setError(e instanceof Error ? e.message : "Account creation failed."); }
    finally { setBusy(false); }
  }
  async function update(id: number, payload: { role?: UserRole; is_active?: boolean }) {
    setBusy(true); setError(""); setNotice("");
    try { await updateAdminUser(id, payload); await refresh(); setNotice("User account updated."); }
    catch (e) { setError(e instanceof Error ? e.message : "User update failed."); }
    finally { setBusy(false); }
  }
  return <section className="panel data-panel admin-users">
    <div className="panel-heading"><div><p className="eyebrow">IDENTITY & ACCESS MANAGEMENT</p><h3>Workspace users</h3></div><span className="tag">{users.length} accounts</span></div>
    <p className="integration-note">Only administrators can provision accounts or change roles. Passwords are hashed by the API and are never returned in user records.</p>
    {error && <div className="error-banner" role="alert">{error}</div>}{notice && <div className="success-banner" role="status">{notice}</div>}
    <form className="nuclei-target-form" onSubmit={create}>
      <label>Email address<input type="email" required maxLength={320} value={email} onChange={e=>setEmail(e.target.value)} placeholder="analyst@organization.com"/></label>
      <label>Temporary password<input type="password" required minLength={12} maxLength={128} autoComplete="new-password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="At least 12 characters"/></label>
      <label>Role<select value={role} onChange={e=>setRole(e.target.value as UserRole)}><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Administrator</option></select></label>
      <button className="primary-button compact" disabled={busy}>Create account</button>
    </form>
    <div className="table-wrap"><table><thead><tr><th>Account</th><th>Role</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead><tbody>{users.map(account=><tr key={account.id}><td><strong>{account.email}</strong><small>USER-{account.id}{account.id===currentUser.id?" · YOU":""}</small></td><td><select aria-label={"Role for "+account.email} disabled={busy || account.id===currentUser.id} value={account.role} onChange={e=>void update(account.id,{role:e.target.value as UserRole})}><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Admin</option></select></td><td><span className="tag">{account.is_active?"Active":"Disabled"}</span></td><td>{new Date(account.created_at).toLocaleDateString()}</td><td><button className="secondary-button compact" disabled={busy || account.id===currentUser.id} onClick={()=>void update(account.id,{is_active:!account.is_active})}>{account.is_active?"Deactivate":"Activate"}</button></td></tr>)}</tbody></table></div>
  </section>;
}
