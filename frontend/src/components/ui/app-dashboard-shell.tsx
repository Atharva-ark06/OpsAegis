import { useState, type ReactNode } from "react";

export interface DashboardNavItem {
  id: string;
  label: string;
  short: string;
  badge?: string;
}

export interface AppDashboardShellProps {
  workspace: { name: string; plan: string };
  user: { name: string; email: string; role?: string };
  nav: DashboardNavItem[];
  activeId: string;
  onNavigate: (id: string) => void;
  onLogout: () => void;
  searchValue?: string;
  onSearchChange?: (value: string) => void;
  showSearch?: boolean;
  headerActions?: ReactNode;
  children: ReactNode;
}

function NavGlyph({ id }: { id: string }) {
  const common = { width: 18, height: 18, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.7, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, "aria-hidden": true as const };
  const paths: Record<string, ReactNode> = {
    overview: <><rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.5"/></>,
    assets: <><path d="m12 3 8 4.5v9L12 21l-8-4.5v-9L12 3Z"/><path d="m4.5 7.7 7.5 4.4 7.5-4.4M12 12v9"/></>,
    findings: <><path d="M12 3 21 19H3L12 3Z"/><path d="M12 9v4m0 3h.01"/></>,
    vulnerabilities: <><path d="M12 3v18M3 12h18"/><circle cx="12" cy="12" r="9"/><path d="m8.5 8.5 7 7m0-7-7 7"/></>,
    detections: <><path d="M3 12s3.2-7 9-7 9 7 9 7-3.2 7-9 7-9-7-9-7Z"/><circle cx="12" cy="12" r="2.7"/></>,
    incidents: <><path d="M12 3 4 6v5c0 5 3.4 8.2 8 10 4.6-1.8 8-5 8-10V6l-8-3Z"/><path d="m9 12 2 2 4-4"/></>,
    integrations: <><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><path d="M17.5 14v7m-3.5-3.5h7"/></>,
    "threat-intel": <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2m-9-2h2m8 0h2"/></>,
    playbooks: <><path d="M5 4.5A2.5 2.5 0 0 1 7.5 2H20v17H7.5A2.5 2.5 0 0 0 5 21.5v-17Z"/><path d="M5 17.5A2.5 2.5 0 0 1 7.5 15H20M9 6h7m-7 4h7"/></>,
    users: <><path d="M16 20v-1.5a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4V20"/><circle cx="10" cy="7.5" r="3.5"/><path d="M20 20v-1.5a4 4 0 0 0-3-3.87M16 4.2a3.5 3.5 0 0 1 0 6.6"/></>,
  };
  return <svg {...common}>{paths[id] ?? <circle cx="12" cy="12" r="8"/>}</svg>;
}

export function AppDashboardShell({
  workspace, user, nav, activeId, onNavigate, onLogout, searchValue = "",
  onSearchChange, showSearch = false, headerActions, children,
}: AppDashboardShellProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const active = nav.find((item) => item.id === activeId);
  const initials = user.name.trim().split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase() || "OA";

  const sidebar = (
    <aside className={["aegis-sidebar", collapsed ? "is-collapsed" : "", mobileOpen ? "is-mobile-open" : ""].filter(Boolean).join(" ")}>
      <div className="aegis-workspace">
        <div className="aegis-brand-mark" aria-hidden="true">OA</div>
        {!collapsed && <div className="aegis-workspace-copy"><strong>{workspace.name}</strong><span>{workspace.plan}</span></div>}
        <span className="aegis-workspace-chevron" aria-hidden="true">⌄</span>
      </div>
      <nav className="aegis-nav" aria-label="Primary navigation">
        {nav.map((item) => (
          <button key={item.id} type="button" className={["aegis-nav-item", activeId === item.id ? "is-active" : ""].filter(Boolean).join(" ")}
            aria-current={activeId === item.id ? "page" : undefined}
            title={collapsed ? item.label : undefined}
            onClick={() => { onNavigate(item.id); setMobileOpen(false); }}>
            <NavGlyph id={item.id}/>
            {!collapsed && <span className="aegis-nav-label">{item.label}</span>}
            {!collapsed && item.badge && <span className="aegis-nav-badge">{item.badge}</span>}
            {collapsed && item.badge && <span className="aegis-nav-dot" aria-hidden="true"/>}
          </button>
        ))}
      </nav>
      <div className="aegis-sidebar-bottom">
        <div className="aegis-session-status"><span className="aegis-status-dot"/> {!collapsed && <span>Authenticated API session</span>}</div>
        <div className="aegis-user-row">
          <span className="aegis-avatar">{initials}</span>
          {!collapsed && <span className="aegis-user-copy"><strong>{user.name}</strong><small>{user.email}</small></span>}
          <button type="button" className="aegis-logout" onClick={onLogout} aria-label="Sign out" title="Sign out">↗</button>
        </div>
        <button type="button" className="aegis-collapse" onClick={() => setCollapsed((value) => !value)} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
          {collapsed ? "»" : "«"} {!collapsed && <span>Collapse sidebar</span>}
        </button>
      </div>
    </aside>
  );

  return (
    <div className="aegis-shell">
      {sidebar}
      {mobileOpen && <button className="aegis-mobile-backdrop" aria-label="Close navigation" onClick={() => setMobileOpen(false)}/>}
      <div className="aegis-main">
        <header className="aegis-topbar">
          <button type="button" className="aegis-mobile-menu" onClick={() => setMobileOpen(true)} aria-label="Open navigation">☰</button>
          <div className="aegis-breadcrumb"><span>{workspace.name}</span><i>/</i><strong>{active?.label ?? "Overview"}</strong></div>
          <div className="aegis-topbar-actions">
            {showSearch && <label className="aegis-search"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="10.8" cy="10.8" r="6.3"/><path d="m16 16 4.5 4.5"/></svg><input aria-label="Search current records" value={searchValue} onChange={(event) => onSearchChange?.(event.target.value)} placeholder="Search records"/><kbd>/</kbd></label>}
            {headerActions}
          </div>
        </header>
        <main className="aegis-content">
          <div className="aegis-page-heading"><div><h1>{active?.label ?? "Overview"}</h1><p>Security operations · verified records from your connected services</p></div></div>
          {children}
        </main>
      </div>
    </div>
  );
}

export default AppDashboardShell;
